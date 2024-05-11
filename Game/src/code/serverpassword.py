import random
import string


class Verifier:

    def __init__(self):
        random.seed(12345)

    def run(self):

        return self.generate_password()

    def generate_password(self, length=34):
        """

        :param length:
        :return:
        """

        uppercase_letters = string.ascii_uppercase
        lowercase_letters = string.ascii_lowercase

        digits = string.digits
        special_characters = '!@#$%^&*()_+[]{}|;:,.<>?'

        password = []
        password.append(random.choice(uppercase_letters))

        password.append(random.choice(lowercase_letters))
        password.append(random.choice(digits))

        password.append(random.choice(special_characters))

        remaining_length = length - 4
        password.extend(
            random.choices(uppercase_letters + lowercase_letters + digits + special_characters, k=remaining_length))

        random.shuffle(password)
        return ''.join(password)
