"""Setup時にだけ配置する、外部アプリ不要の無害な観測用文書。"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import zipfile

SCHEMA = 'r_AKanaly-observation-documents-v1'


# Office文書を実形式で生成し、再検証時も同じハッシュになるようZIP日時を固定する。
def office_document(kind, number):
    buffer = io.BytesIO()
    if kind == 'docx':
        main = 'word/document.xml'
        mime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
        entries = {main: '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Fictional meeting %d. Synthetic analysis document.</w:t></w:r></w:p></w:body></w:document>' % number}
        extra = ''
    else:
        main = 'xl/workbook.xml'
        mime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'
        entries = {
            main: '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Budget" sheetId="1" r:id="rId1"/></sheets></workbook>',
            'xl/_rels/workbook.xml.rels': '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            'xl/worksheets/sheet1.xml': '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Fictional budget</t></is></c><c r="B1"><v>%d</v></c></row></sheetData></worksheet>' % number,
        }
        extra = '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    entries['[Content_Types].xml'] = '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/%s" ContentType="%s"/>%s</Types>' % (main, mime, extra)
    entries['_rels/.rels'] = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="%s"/></Relationships>' % main
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name, text in sorted(entries.items()):
            archive.writestr(zipfile.ZipInfo(name), text.encode('utf-8'))
    return buffer.getvalue()


# 実在の情報や実行コードを含めず、六形式を四組用意する。
def documents():
    result = {}
    for number in range(1, 5):
        result[f'note_{number:02}.txt'] = f'Synthetic observation note {number}. No personal data.\n'.encode()
        result[f'budget_{number:02}.csv'] = f'Item,Quantity,Price\r\nPaper,{number},500\r\n'.encode()
        result[f'minutes_{number:02}.rtf'] = ('{\\rtf1\\ansi Fictional meeting %d. Synthetic observation file.}' % number).encode()
        result[f'reference_{number:02}.html'] = f'<!doctype html><html><head><meta charset="utf-8"><title>Fictional reference</title></head><body><p>Synthetic reference {number}</p></body></html>'.encode()
        for kind in ('docx', 'xlsx'):
            result[f'document_{number:02}.{kind}'] = office_document(kind, number)
    return result


# ジャンクションを経由して別の利用者フォルダを変更・参照しない。
def checked_path(path):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        if item.is_symlink() or (item.exists() and getattr(item.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError('Observation documents cannot use reparse points')
    return path


# 自前の文書集合と照合し、書き換えられた目録や既存ファイルを採用しない。
def verify(destination):
    destination = checked_path(destination)
    expected = documents()
    manifest = {'schema': SCHEMA, 'files': [dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest()) for name, data in sorted(expected.items())]}
    actual = json.loads(checked_path(destination/'baseline.json').read_text(encoding='utf-8'))
    if actual != manifest or set(p.name for p in destination.iterdir()) != set(expected) | {'baseline.json'}:
        raise ValueError('Observation document inventory differs; existing files preserved')
    for name, data in expected.items():
        path = checked_path(destination/name)
        if path.stat().st_size != len(data) or path.read_bytes() != data:
            raise ValueError('Observation document differs: '+name)
    return dict(complete=True, count=len(expected), schema=SCHEMA)


# 新規専用フォルダだけを確定し、再実行では照合のみ行って上書きしない。
def populate(destination):
    destination = checked_path(destination)
    if destination.exists():
        return verify(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rAK-documents-', dir=destination.parent) as temp:
        staging = Path(temp)/'documents'
        staging.mkdir()
        files = []
        for name, data in sorted(documents().items()):
            (staging/name).write_bytes(data)
            files.append(dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
        (staging/'baseline.json').write_text(json.dumps(dict(schema=SCHEMA, files=files), indent=2), encoding='utf-8')
        verify(staging)
        staging.rename(destination)
    return verify(destination)


# 呼出元のGuest確認を前提に、明示した専用配置先だけを扱う。
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--destination', required=True)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    result = verify(args.destination) if args.verify else populate(args.destination)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
