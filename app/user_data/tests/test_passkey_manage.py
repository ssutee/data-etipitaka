import pytest

from user_data import passkey_manage as manage

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
