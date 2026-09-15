import threading

import pytest
from django.db import connection

from user_data import passkey_manage as manage
from user_data.models import Passkey

from .conftest import add_passkey
from .soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.django_db


def _drop_password(user):
    user.set_unusable_password()
    user.save()


def test_list_passkeys(alice, authenticator):
    passkey = add_passkey(alice, authenticator, name='Phone')
    assert manage.list_passkeys(alice) == {
        'has_password': True,
        'passkeys': [{'id': passkey.pk, 'name': 'Phone', 'authenticator': '',
                      'backed_up': True, 'created_at': passkey.created_at.isoformat(),
                      'last_used_at': None}]}


def test_list_passkeys_orders_by_created_at_then_pk(alice, authenticator):
    first = add_passkey(alice, authenticator, name='First')
    second = add_passkey(alice, SoftAuthenticator(), name='Second')
    # Force a tie on created_at so the listing can only be putting `second`
    # after `first` because of the pk tiebreaker, not just insertion luck.
    Passkey.objects.filter(pk__in=[first.pk, second.pk]).update(created_at=first.created_at)
    assert [p['id'] for p in manage.list_passkeys(alice)['passkeys']] == [first.pk, second.pk]


def test_rename_passkey(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    assert manage.rename_passkey(alice, passkey.pk, '  Laptop ').name == 'Laptop'


def test_rename_accepts_a_valid_string_id(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    assert manage.rename_passkey(alice, str(passkey.pk), 'Tablet').pk == passkey.pk


@pytest.mark.parametrize('name', ['', '   ', None, 5])
def test_rename_rejects_blank_name(alice, authenticator, name):
    passkey = add_passkey(alice, authenticator)
    with pytest.raises(manage.InvalidName):
        manage.rename_passkey(alice, passkey.pk, name)


def test_rename_rejects_zero_width_space_only_name(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    with pytest.raises(manage.InvalidName):
        manage.rename_passkey(alice, passkey.pk, chr(0x200B))


def test_rename_collapses_a_newline(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    assert manage.rename_passkey(alice, passkey.pk, 'My\nPhone').name == 'My Phone'


def test_rename_racing_a_delete_is_not_found(alice, authenticator, monkeypatch):
    """clean_name runs after _own's lookup but before the update -- exactly
    where a concurrent delete_passkey would land -- so deleting the row
    from inside it stands in for that race without needing real threads."""
    passkey = add_passkey(alice, authenticator)
    real_clean_name = manage.clean_name

    def _delete_then_clean(name):
        Passkey.objects.filter(pk=passkey.pk).delete()
        return real_clean_name(name)

    monkeypatch.setattr(manage, 'clean_name', _delete_then_clean)
    with pytest.raises(manage.NotFound):
        manage.rename_passkey(alice, passkey.pk, 'Laptop')


def test_other_users_passkey_is_not_found(alice, bob, authenticator):
    passkey = add_passkey(bob, authenticator)
    with pytest.raises(manage.NotFound):
        manage.rename_passkey(alice, passkey.pk, 'x')
    with pytest.raises(manage.NotFound):
        manage.delete_passkey(alice, passkey.pk)


def test_rename_resolves_ownership_before_validating_the_name(alice, bob, authenticator):
    """Another user's id is NotFound even when the name would also be invalid."""
    passkey = add_passkey(bob, authenticator)
    with pytest.raises(manage.NotFound):
        manage.rename_passkey(alice, passkey.pk, '')


def test_bad_id_is_not_found(alice):
    with pytest.raises(manage.NotFound):
        manage.delete_passkey(alice, 'abc')


@pytest.mark.parametrize('bad_id', [
    True, 1.9, ' 7 ', '٧', '-1', '9' * 30, None, [1], {'id': 1}, 3.0,
])
def test_strictly_typed_bad_ids_are_not_found(alice, bad_id):
    with pytest.raises(manage.NotFound):
        manage.delete_passkey(alice, bad_id)


def test_id_above_int4_ceiling_is_not_found(alice):
    # 10 digits (within the regex's own length cap) but over 2147483647.
    with pytest.raises(manage.NotFound):
        manage.delete_passkey(alice, '9999999999')


def test_delete_last_passkey_allowed_with_password(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    manage.delete_passkey(alice, passkey.pk)
    assert not alice.passkeys.exists()


def test_delete_last_passkey_refused_without_password(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    _drop_password(alice)
    with pytest.raises(manage.LockoutGuard):
        manage.delete_passkey(alice, passkey.pk)
    add_passkey(alice, SoftAuthenticator())
    manage.delete_passkey(alice, passkey.pk)  # another passkey remains
    assert alice.passkeys.count() == 1


def test_delete_already_deleted_passkey_is_not_found(alice, authenticator):
    passkey = add_passkey(alice, authenticator)
    manage.delete_passkey(alice, passkey.pk)
    with pytest.raises(manage.NotFound):
        manage.delete_passkey(alice, passkey.pk)


def test_remove_password(alice, authenticator):
    add_passkey(alice, authenticator)
    assert manage.remove_password(alice, 'alicepass123').has_usable_password() is False
    alice.refresh_from_db()
    assert alice.has_usable_password() is False


def test_remove_password_requires_passkey(alice):
    with pytest.raises(manage.LockoutGuard):
        manage.remove_password(alice, 'alicepass123')


@pytest.mark.parametrize('password', ['wrong', None, '\ud800', 12345, ''])
def test_remove_password_requires_correct_password(alice, authenticator, password):
    add_passkey(alice, authenticator)
    with pytest.raises(manage.WrongPassword):
        manage.remove_password(alice, password)


def test_remove_password_twice_is_lockout_guard(alice, authenticator):
    add_passkey(alice, authenticator)
    manage.remove_password(alice, 'alicepass123')
    alice.refresh_from_db()
    with pytest.raises(manage.LockoutGuard):
        manage.remove_password(alice, 'alicepass123')


@pytest.mark.django_db(transaction=True)
def test_concurrent_deletes_of_a_passwordless_users_last_two_passkeys(alice):
    """A passwordless account with exactly two passkeys: two real threads
    each try to delete a different one at the same moment. delete_passkey's
    select_for_update() lock on the user row must serialize them -- one
    thread deletes its passkey and commits, then the other's own lock
    acquisition sees only one passkey left and is refused -- so the two
    threads can never both succeed and leave the account with none."""
    _drop_password(alice)
    first = add_passkey(alice, SoftAuthenticator())
    second = add_passkey(alice, SoftAuthenticator())

    start = threading.Barrier(2)
    results = {}

    def _delete(name, passkey_id):
        try:
            start.wait(timeout=5)
            manage.delete_passkey(alice, passkey_id)
            results[name] = 'ok'
        except manage.LockoutGuard:
            results[name] = 'guard'
        except Exception as exc:  # pragma: no cover - surfaced via the assertion below
            results[name] = repr(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=_delete, args=('a', first.pk)),
              threading.Thread(target=_delete, args=('b', second.pk))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    outcomes = list(results.values())
    assert outcomes.count('ok') == 1, results
    assert outcomes.count('guard') == 1, results
    assert Passkey.objects.filter(user=alice).count() == 1
