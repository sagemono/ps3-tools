# syscon_uart.py
# A modified version of M4j0rs script

from binascii import unhexlify as uhx
from Cryptodome.Cipher import AES
import os
import string
import sys
import signal
import time
from datetime import datetime
import threading
import queue

class PS3UART(object):
    try:
       import serial
    except ImportError:
       print('Error: The pyserial and pycryptodome modules are required. You can install it with "pip install pyserial pycryptodomex"')
       sys.exit(1)

    type = ''

    sc2tb = uhx('71f03f184c01c5ebc3f6a22a42ba9525')
    tb2sc = uhx('907e730f4d4e0a0b7b75f030eb1d9d36')
    value = uhx('3350BD7820345C29056A223BA220B323')
    zero  = uhx('00000000000000000000000000000000')

    auth1r_header = uhx('10100000FFFFFFFF0000000000000000')
    auth2_header  = uhx('10010000000000000000000000000000')

    def aes_decrypt_cbc(self, key, iv, in_data):
        return AES.new(key, AES.MODE_CBC, iv).decrypt(in_data)

    def aes_encrypt_cbc(self, key, iv, in_data):
        return AES.new(key, AES.MODE_CBC, iv).encrypt(in_data)

    def __init__(self, port, type):
        import serial
        self.ser = serial.Serial()
        self.ser.port = port

        if (type == 'CXR' or type == 'SW'):
            self.ser.baudrate = 57600
        elif (type == 'CXRF'):
            self.ser.baudrate = 115200
        else:
            raise ValueError("Unknown type: " + str(type))

        self.type = type
        self.ser.timeout = 0.1

        try:
            if getattr(self.ser, 'is_open', False):
                self.ser.close()
            else:
                if hasattr(self.ser, 'isOpen') and self.ser.isOpen():
                    self.ser.close()
        except Exception:
            pass

        try:
            self.ser.open()
        except serial.SerialException as e:
            if "already open" not in str(e).lower():
                raise

        if hasattr(self.ser, 'is_open'):
            assert self.ser.is_open
        else:
            assert self.ser.isOpen()

        try:
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
        except Exception:
            self.ser.flushInput()
            self.ser.flushOutput()

        self._rx_queue = queue.Queue()
        self._reader_thread = None
        self._reader_stop = threading.Event()
        self._line_buffer = b''
        self._last_activity = time.time()
        self.trace = None
        self._start_reader()

    def _start_reader(self):
        def reader():
            while not self._reader_stop.is_set():
                try:
                    n = 0
                    try:
                        n = self.ser.in_waiting if hasattr(self.ser, 'in_waiting') else self.ser.inWaiting()
                    except Exception:
                        n = 0

                    if n:
                        b = self.ser.read(n)
                        if not b:
                            time.sleep(0.01)
                            continue

                        self._rx_queue.put(b)

                        self._line_buffer += b
                        self._last_activity = time.time()

                        while b'\n' in self._line_buffer:
                            line_bytes, self._line_buffer = self._line_buffer.split(b'\n', 1)
                            if line_bytes.endswith(b'\r'):
                                line_bytes = line_bytes[:-1]
                            try:
                                text = line_bytes.decode('utf-8', 'replace')
                            except Exception:
                                text = line_bytes.decode('latin1', 'replace')
                            ts = datetime.now().isoformat(timespec='milliseconds')
                            hex_preview = line_bytes.hex()
                            if len(hex_preview) > 80:
                                hex_preview = hex_preview[:77] + '...'
                            try:
                                import readline
                                cur = readline.get_line_buffer()
                                sys.stdout.write('\r')
                                sys.stdout.write(f"[{ts}] LIVE RX: {text}\n")
                                sys.stdout.write('>$ ' + cur)
                                sys.stdout.flush()
                                try:
                                    readline.redisplay()
                                except Exception:
                                    pass
                            except Exception:
                                print(f"[{ts}] LIVE RX: {text}")
                    else:
                        if self._line_buffer and (time.time() - self._last_activity) > 0.5:
                            chunk = self._line_buffer
                            self._line_buffer = b''
                            try:
                                text = chunk.decode('utf-8', 'replace')
                            except Exception:
                                text = chunk.decode('latin1', 'replace')
                            ts = datetime.now().isoformat(timespec='milliseconds')
                            try:
                                import readline
                                cur = readline.get_line_buffer()
                                sys.stdout.write('\r')
                                sys.stdout.write(f"[{ts}] LIVE RX(partial): {text}\n")
                                sys.stdout.write('>$ ' + cur)
                                sys.stdout.flush()
                                try:
                                    readline.redisplay()
                                except Exception:
                                    pass
                            except Exception:
                                print(f"[{ts}] LIVE RX(partial): {text}")
                        time.sleep(0.01)
                except Exception:
                    time.sleep(0.1)
                    continue

        self._reader_thread = threading.Thread(target=reader, daemon=True)
        self._reader_thread.start()

    def _log_tx(self, b: bytes):
        if not self.trace: return
        ts = datetime.now().isoformat(timespec='milliseconds')
        self.trace.write(f"[{ts}] TX {len(b):4d}: {b.hex()}\n")

    def _log_rx(self, b: bytes):
        if not self.trace or not b: return
        ts = datetime.now().isoformat(timespec='milliseconds')
        self.trace.write(f"[{ts}] RX {len(b):4d}: {b.hex()}\n")

    def tap_rx(self, ms=200):
        end = time.time() + (ms/1000.0)
        chunks = []
        while time.time() < end:
            try:
                while True:
                    b = self._rx_queue.get_nowait()
                    chunks.append(b)
                    self._rx_queue.task_done()
            except queue.Empty:
                pass
            time.sleep(0.005)
        if chunks:
            return b''.join(chunks)
        return b''

    def __del__(self):
        try:
            self._reader_stop.set()
            if self._reader_thread:
                self._reader_thread.join(timeout=0.2)
        except Exception:
            pass
        try:
            if hasattr(self.ser, 'is_open') and self.ser.is_open:
                self.ser.close()
            elif hasattr(self.ser, 'isOpen') and self.ser.isOpen():
                self.ser.close()
        except Exception:
            pass

    def send(self, data):
        b = data.encode('ascii', 'ignore')
        self.ser.write(b)
        self._log_tx(b)

    def receive(self):
        collected = []
        try:
            while True:
                b = self._rx_queue.get_nowait()
                collected.append(b)
                self._rx_queue.task_done()
        except queue.Empty:
            pass
        if collected:
            data = b''.join(collected)
            self._log_rx(data)
            return data
        return b""

    def command(self, com, wait = 1, verbose = False):
        if(verbose):
            print('Command: ' + com)

        if(self.type == 'CXR'):
            length = len(com)
            checksum = sum(bytearray(com, 'ascii')) % 0x100
            if(length <= 10):
                self.send('C:{:02X}:{}\r\n'.format(checksum, com))
            else:
                j = 10
                self.send('C:{:02X}:{}'.format(checksum, com[0:j]))
                for i in range(length - j, 15, -15):
                    self.send(com[j:j+15])
                    j += 15
                self.send(com[j:] + '\r\n')
        elif(self.type == 'SW'):
            length = len(com)
            if(length >= 0x40):
                if(self.command('SETCMDLONG FF FF')[0] != 0):
                    return (0xFFFFFFFF, ['Setcmdlong'])
            checksum = sum(bytearray(com, 'ascii')) % 0x100
            self.send('{}:{:02X}\r\n'.format(com, checksum))
        else:
            self.send(com + '\r\n')

        time.sleep(wait)
        answer = self.receive().decode('ascii', 'ignore').strip()
        if(verbose):
            print('Answer: ' + answer)

        if(self.type == 'CXR'):
            answer = answer.split(':')
            if(len(answer) != 3):
                return (0xFFFFFFFF, ['Answer length'])
            checksum = sum(bytearray(answer[2], 'ascii')) % 0x100
            if(answer[0] != 'R' and answer[0] != 'E'):
                return (0xFFFFFFFF, ['Magic'])
            if(answer[1] != '{:02X}'.format(checksum)):
                return (0xFFFFFFFF, ['Checksum'])
            data = answer[2].split(' ')
            if(answer[0] == 'R' and len(data) < 2 or answer[0] == 'E' and len(data) != 2):
                return (0xFFFFFFFF, ['Data length'])
            if(data[0] != 'OK' or len(data) < 2):
                return (int(data[1], 16), [])
            else:
                return (int(data[1], 16), data[2:])
        elif(self.type == 'SW'):
            answer = answer.split('\n')
            for i in range(0, len(answer)):
                answer[i] = answer[i].replace('\n', '').rsplit(':', 1)
                if(len(answer[i]) != 2):
                    return (0xFFFFFFFF, ['Answer length'])
                checksum = sum(bytearray(answer[i][0], 'ascii')) % 0x100
                if(answer[i][1] != '{:02X}'.format(checksum)):
                    return (0xFFFFFFFF, ['Checksum'])
                answer[i][0] += '\n'
            ret = answer[-1][0].replace('\n', '').split(' ')
            if(len(ret) < 2 or len(ret[1]) != 8 and not all(c in string.hexdigits for c in ret[1])):
                return (0, [x[0] for x in answer])
            elif(len(answer) == 1):
                return (int(ret[1], 16), ret[2:])
            else:
                return (int(ret[1], 16), [x[0] for x in answer[:-1]])
        else:
            return (0, [answer])

    def auth(self):
        if(self.type == 'CXR' or self.type == 'SW'):
            auth1r = self.command('AUTH1 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
            if(auth1r[0] == 0 and auth1r[1] != []):
                auth1r = uhx(auth1r[1][0])
                if(auth1r[0:0x10] == self.auth1r_header):
                    data = self.aes_decrypt_cbc(self.sc2tb, self.zero, auth1r[0x10:0x40])
                    if(data[0x8:0x10] == self.zero[0x0:0x8] and data[0x10:0x20] == self.value and data[0x20:0x30] == self.zero):
                        new_data = data[0x8:0x10] + data[0x0:0x8] + self.zero + self.zero
                        auth2_body = self.aes_encrypt_cbc(self.tb2sc, self.zero, new_data)
                        auth2r = self.command('AUTH2 ' + ''.join('{:02X}'.format(c) for c in bytearray(self.auth2_header + auth2_body)))
                        if(auth2r[0] == 0):
                            return 'Auth successful'
                        else:
                            return 'Auth failed'
                    else:
                        return 'Auth1 response body invalid'
                else:
                    return 'Auth1 response header invalid'
            else:
                return 'Auth1 response invalid'
        else:
            scopen = self.command('scopen')
            if('SC_READY' in scopen[1][0]):
                auth1r = self.command('10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
                auth1r = auth1r[1][0].split('\r')[1][1:]
                if(len(auth1r) == 128):
                    auth1r = uhx(auth1r)
                    if(auth1r[0:0x10] == self.auth1r_header):
                        data = self.aes_decrypt_cbc(self.sc2tb, self.zero, auth1r[0x10:0x40])
                        if(data[0x8:0x10] == self.zero[0x0:0x8] and data[0x10:0x20] == self.value and data[0x20:0x30] == self.zero):
                            new_data = data[0x8:0x10] + data[0x0:0x8] + self.zero + self.zero
                            auth2_body = self.aes_encrypt_cbc(self.tb2sc, self.zero, new_data)
                            auth2r = self.command(''.join('{:02X}'.format(c) for c in bytearray(self.auth2_header + auth2_body)))
                            if('SC_SUCCESS' in auth2r[1][0]):
                                return 'Auth successful'
                            else:
                                return 'Auth failed'
                        else:
                            return 'Auth1 response body invalid'
                    else:
                        return 'Auth1 response header invalid'
                else:
                    return 'Auth1 response invalid'
            else:
                return 'scopen response invalid'


def main(argc, argv):
    if(argc < 3):
        print(os.path.basename(__file__) + ' <serial port> <sc type ["CXR", "CXRF", "SW"]> <Optional:[-l log.txt]> [--no-live]')
        sys.exit(1)

    no_live = '--no-live' in argv

    ps3 = PS3UART(argv[1], argv[2])

    ps3.live_text_mode = not no_live

    raw_input_c = vars(__builtins__).get('raw_input', input)

    if '-l' in argv:
        log_file = open(argv[argv.index('-l') + 1], 'a', buffering=1)
        print('Logging enabled. Writing to ' + argv[argv.index('-l') + 1])
        ps3.trace = log_file
    else:
        log_file = None

    if log_file:
        ps3.trace = log_file

    def sigint_handler(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGINT, sigint_handler)

    while True:
        if log_file:
            ps3.tap_rx(50)

        print('Press Ctrl+C to exit')
        try:
           in_data = raw_input_c('>$ ')
           if(in_data.lower() == 'auth'):
              print(ps3.auth())
              continue

           ret = ps3.command(in_data)

           if not getattr(ps3, 'live_text_mode', False):
               if(argv[2] == 'CXR'):
                   output = '{:08X}'.format(ret[0]) + ' ' + ' '.join(ret[1])
               elif(argv[2] == 'SW'):
                   if(len(ret[1]) > 0 and '\n' not in ret[1][0]):
                       output = '{:08X}'.format(ret[0]) + ' ' + ' '.join(ret[1])
                   else:
                       output = '{:08X}'.format(ret[0]) + '\n' + ''.join(ret[1])
               else:
                   output = ret[1][0]
               print(output)
               if log_file:
                    log_file.write(output + '\n')
           else:
               pass

        except KeyboardInterrupt:
            print('\nExiting...')
            if log_file:
                log_file.close()
            ps3._reader_stop.set()
            if ps3._reader_thread:
                ps3._reader_thread.join(timeout=0.2)
            break

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
