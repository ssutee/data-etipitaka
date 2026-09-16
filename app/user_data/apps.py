from django.apps import AppConfig


class UserDataConfig(AppConfig):
    name = 'user_data'

    def ready(self):
        from user_data import checks  # noqa: F401 -- registers system checks
