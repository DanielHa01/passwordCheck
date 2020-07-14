# Author: Daniel Ha
# This programm check how many times does your password got hacked by using pwedpasswords.com
import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check your api and run again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def print_available_password(pass_list):
    f = open('available_password.txt', 'a')
    for password in pass_list:
        f.write(password)
    f.close()
    return 0

def main(args = 'passwords.txt'):
    f = open(args, 'r')
    available_pass = []
    for password in f:
        new_pass = password.replace('\n', '')
        count = pwned_api_check(new_pass)
        if len(new_pass) < 8:
            print(f'{new_pass} is too short. Password need to be at least 8 characters!!!')
        elif count and int(count) < 10:
            if int(count) == 1:
                print(f'{new_pass} was found {count} time ... you might want to change your password')
            else:
                print(f'{new_pass} was found {count} times ... you might want to change your password')
        elif int(count) >= 10:
            print(f'{new_pass} was found {count} times ... you should change your password')
        else:
            print(f'{new_pass} was not found. You can use this password')
            available_pass.append(password)
    f.close()
    return print_available_password(available_pass)

if __name__ == '__main__':
    main(sys.argv[1])


