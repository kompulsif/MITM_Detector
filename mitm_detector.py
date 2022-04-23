from socket import error, socket, AF_INET, SOCK_STREAM
from subprocess import run, check_output, DEVNULL
from notifypy import Notify
from argparse import ArgumentParser
from termcolor import colored
from platform import system
from random import choice
from time import sleep
from os import environ


def network_checker(cmd: list) -> None:
    print('\r' + colored('[*]-> Network checking... <-[*]', 'yellow'), end='')
    try:
        r = run(cmd, stdout=DEVNULL)
        if (r.returncode != 0):
            display_notification('Please check your internet connection')
            quit()

    except KeyboardInterrupt:
        quit()

    except:
        display_notification('Please check your internet connection')
        quit()


def network_id_finder() -> None:
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect(('1.1.1.1', 80))
        host_addr = s.getsockname()[0]
        s.close()

    except error:
        display_notification('Please check your internet connection')
        quit()

    first_octet = int(host_addr.split('.')[0])
    network_id = host_addr.split('.')

    if (first_octet in range(1, 128)):
        return network_id[0] + '.'

    elif (first_octet in range(128, 192)):
        return '.'.join(network_id[:2]) + '.'

    elif (first_octet in range(192, 224)):
        return '.'.join(network_id[:3]) + '.'

    else:
        print('[!]-> Invalid local ip! <-[!]')
        quit()


def display_notification(msg: str, title='Information') -> None:
    if (osName == 'Darwin'):
        from pync import notify
        try:
            while True:
                notify('Please check your internet connection')
                sleep(5)

        except:
            notification = Notify()
            notification.application_name = 'MITM DETECTOR'
            notification.title = title
            notification.message = msg
            notification.send()

    elif (osName in ('Windows', 'Linux')):
        notification = Notify()
        notification.application_name = 'MITM DETECTOR'
        notification.title = title
        notification.message = msg
        notification.send()

    quit()


def arp_reader_windows(subip: str) -> dict:
    output = check_output(['arp', '-a']).decode()
    output = [i.strip() for i in output.splitlines()
              if (i.strip().startswith(subip))]
    arp_table = {}

    for i in output:
        l = i.split(' ')
        l = [x for x in l if x not in (' ', '')][:-1]
        arp_table[l[0]] = l[1]

    return arp_table


def arp_reader_darwin(subip: str) -> dict:
    output = check_output(['arp', '-a']).decode()
    output = [i.strip('? (') for i in output.splitlines() if (
        i.strip('? (').startswith(subip))]
    arp_table = {}

    for i in output:
        i = i.split(' ')
        ip = i[0].strip(') ')
        mac = i[2].strip()
        arp_table[ip] = mac

    return arp_table


def arp_reader_linux(subip: str) -> dict:
    with open('/proc/net/arp', 'r') as f:
        arp_table = {}

        for i in f:
            if (i.startswith(subip)):
                i = [x for x in i.split(' ') if (x not in ('', ' '))]
                arp_table[i[0]] = i[3]

        return arp_table


def table_controller(data: dict) -> None:
    counter = []

    for (i, m) in data.items():
        if (m in counter):
            try:
                display_notification('An atack has been detected!', 'Warning')
                quit()
            except:
                quit()

        counter.append(m)


def detector_loop(reader_func, command: list, network_id: str) -> None:
    try:
        while True:
            network_checker(command)
            arp_table = reader_func(network_id)
            table_controller(arp_table)
            print('\r' + colored('Working...'.ljust(50, ' '), random_color()), end='')
            sleep(3)

    except KeyboardInterrupt:
        quit()


def random_color() -> str:
    color_list = ('red', 'green', 'blue', 'magenta', 'cyan')
    return choice(color_list)


def cmd_ps_color() -> bool:
    command1 = 'powershell -Command Set-ItemProperty HKCU:\Console VirtualTerminalLevel -Type DWORD 1'
    command2 = 'powershell -Command Get-ItemPropertyValue HKCU:\Console VirtualTerminalLevel'
    v = run(command2, capture_output=True)

    if (v.returncode != 0) or (v.stdout.strip() != b'1'):
        print('[*]-> Setting terminal color... <-[*]')
        v2 = run(command1)

        if (v2.returncode != 0):
            display_notification(
                'Something went wrong, please give admin permission and try again.', 'Error')
            quit()

        sleep(0.5)
        print('[*]-> Color adjustment is complete. Please close and open the terminal and run the program again. <-[*]')
        quit()

    sleep(0.5)
    return True


def main() -> None:
    command_windows = ['ping', '1.1.1.1', '-n', '1']
    command_darwin_linux = ['ping', '1.1.1.1', '-c', '1']
    network_id = network_id_finder()
    print('\n[*]-> Detector started! <-[*]')

    if (osName == 'Windows'):
        print(f'[*]-> OS detected: Windows <-[*]\n')

        if (cmd_ps_color()):
            detector_loop(arp_reader_windows, command_windows, network_id)

    elif (osName == 'Darwin'):
        print(colored(f'[*]-> OS detected: Darwin <-[*]'))
        detector_loop(arp_reader_darwin, command_darwin_linux, network_id)

    elif (osName == 'Linux'):
        print(colored(f'[*]-> OS detected: Linux <-[*]'))
        detector_loop(arp_reader_linux, command_darwin_linux, network_id)

    else:
        print(
            colored(f'[!]-> OS not supported, please let me know <-[!]', 'red'))


if __name__ == '__main__':
    osName = system()
    main()
