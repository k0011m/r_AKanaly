"""VMwareのlocalhostコンソールで撮影・絶対座標入力を検証するRFBクライアント。"""
import socket
import struct
import time
import zlib


# 分割受信や切断を検出し、不完全な画像を証拠として保存しない。
def receive(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise ConnectionError('RFB connection closed')
        result.extend(part)
    return bytes(result)


# 実験中のlocalhost専用サーバーへ接続し、座標の基準となる画面寸法を取得する。
def connect(port, timeout=10):
    sock = socket.create_connection(('127.0.0.1', port), timeout=timeout)
    version = receive(sock, 12)
    if version != b'RFB 003.008\n':
        sock.close()
        raise RuntimeError(f'Unsupported RFB version: {version!r}')
    sock.sendall(version)
    count = receive(sock, 1)[0]
    security = receive(sock, count)
    if 1 not in security:
        sock.close()
        raise RuntimeError('Console authentication mode is not supported')
    sock.sendall(b'\x01')
    if struct.unpack('!I', receive(sock, 4))[0] != 0:
        raise RuntimeError('RFB security negotiation failed')
    sock.sendall(b'\x01')
    header = receive(sock, 24)
    width, height = struct.unpack('!HH', header[:4])
    name_size = struct.unpack('!I', header[20:24])[0]
    if name_size > 4096 or not (0 < width * height <= 33554432):
        raise RuntimeError('Invalid console dimensions/name')
    receive(sock, name_size)
    # VMwareの標準的なBGRX配置を要求し、PNG側でRGBへ並べ替える。
    # RGBXへの変更を前提にすると、ネイティブ配置で届いた画面の赤青が逆転する。
    pixel_format = struct.pack('!BBBBHHHBBBxxx', 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    sock.sendall(b'\x00\x00\x00\x00' + pixel_format)
    sock.sendall(struct.pack('!BBHi', 2, 0, 1, 0))
    return sock, width, height


# Raw framebuffer全体を一度取得し、解析対象と画像の座標を同一に保つ。
def capture(sock, width, height):
    sock.sendall(struct.pack('!BBHHHH', 3, 0, 0, 0, width, height))
    pixels = bytearray(width * height * 4)
    covered = bytearray(width * height)
    deadline = time.monotonic() + 15
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError('Complete framebuffer was not received')
        kind = receive(sock, 1)[0]
        if kind == 2:
            continue
        if kind != 0:
            raise RuntimeError(f'Unexpected server message {kind}')
        rectangles = struct.unpack('!xH', receive(sock, 3))[0]
        for _ in range(rectangles):
            x, y, rw, rh, encoding = struct.unpack('!HHHHi', receive(sock, 12))
            if encoding != 0 or x + rw > width or y + rh > height:
                raise RuntimeError('Unexpected encoding or framebuffer resize; reobserve')
            data = receive(sock, rw * rh * 4)
            for row in range(rh):
                start = ((y + row) * width + x) * 4
                pixels[start:start + rw * 4] = data[row * rw * 4:(row + 1) * rw * 4]
                covered[start // 4:start // 4 + rw] = b'\x01' * rw
        if all(covered):
            return pixels


# 保存する画像はデスクトップ全体の原寸RGBで、推論座標へ倍率を挟まない。
def png_image(width, height, pixels):
    if len(pixels) != width * height * 4:
        raise ValueError('Invalid BGRX framebuffer length')
    # 各PNGチャンクのCRCを付け、破損した撮影結果を読取側が検出できるようにする。
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))
    rgb = bytearray(width * height * 3)
    # RFBで指定したリトルエンディアンのBGRXをPNGのRGBへ変換する。
    rgb[0::3], rgb[1::3], rgb[2::3] = pixels[2::4], pixels[1::4], pixels[0::4]
    scanlines = b''.join(b'\x00' + rgb[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(scanlines)) + chunk(b'IEND', b''))


class ConsoleInput:
    # 接続先をlocalhostと指定ポートだけに固定する。
    def __init__(self, port, timeout=10):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('Invalid local console port')
        self.port, self.timeout = port, timeout

    # 画面取得は常に完全な原寸フレームを返す。
    def observe(self):
        sock, width, height = connect(self.port, self.timeout)
        with sock:
            pixels = capture(sock, width, height)
        return width, height, png_image(width, height, pixels)

    # 再接続後の解像度も照合してから入力し、送信失敗を自動再試行しない。
    def click(self, width, height, x, y):
        if any(type(v) is not int for v in (width, height, x, y)):
            raise ValueError('Pixel coordinates must be integers')
        sock, current_width, current_height = connect(self.port, self.timeout)
        with sock:
            if (width, height) != (current_width, current_height):
                raise ValueError('Frame dimensions changed; observe again')
            if not (0 <= x < width and 0 <= y < height):
                raise ValueError('Point is outside the observed frame')
            sock.sendall(struct.pack('!BBHH', 5, 0, x, y))
            sock.sendall(struct.pack('!BBHH', 5, 1, x, y))
            try:
                time.sleep(0.05)
            finally:
                sock.sendall(struct.pack('!BBHH', 5, 0, x, y))

    # キーはX11 keysymを用い、Hostのキーボード状態には触れない。
    def key(self, width, height, keysym):
        if type(keysym) is not int or not 0 <= keysym <= 0x1fffffff:
            raise ValueError('Invalid keysym')
        sock, current_width, current_height = connect(self.port, self.timeout)
        with sock:
            if (width, height) != (current_width, current_height):
                raise ValueError('Frame dimensions changed; observe again')
            sock.sendall(struct.pack('!BBHI', 4, 1, 0, keysym))
            sock.sendall(struct.pack('!BBHI', 4, 0, 0, keysym))
