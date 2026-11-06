"""工程の成否とは別に、保存済みの正常レポートを確認する。"""
import json
from pathlib import Path
import zipfile


# 正常生成metadataと空でないレポート本文を、通常フォルダまたは完成ZIPから確認する。
def inspect_report(directory):
    root = Path(directory)
    archive = root.with_name(root.name + '.zip')
    try:
        if root.is_dir() and (root / 'metadata.json').is_file():
            metadata = json.loads((root / 'metadata.json').read_text(encoding='utf-8-sig'))
            name = Path(metadata.get('output_paths', {}).get('report', '')).name
            if metadata.get('success') is not True or name not in ('analysis.html', 'analysis.md'):
                return {'success': False, 'reason': '正常レポートの生成記録がありません'}
            content = (root / name).read_text(encoding='utf-8-sig')
            location = str(root / name)
        elif archive.is_file():
            with zipfile.ZipFile(archive) as saved:
                metadata = json.loads(saved.read('metadata.json').decode('utf-8-sig'))
                name = Path(metadata.get('output_paths', {}).get('report', '')).name
                if metadata.get('success') is not True or name not in ('analysis.html', 'analysis.md'):
                    return {'success': False, 'reason': '正常レポートの生成記録がありません'}
                content = saved.read(name).decode('utf-8-sig')
                location = str(archive) + ' / ' + name
        else:
            return {'success': False, 'reason': '正常レポートの保存先がありません'}
        return {'success': bool(content.strip()), 'report': location,
                'reason': '正常レポートの生成・保存を確認' if content.strip() else 'レポートが空です'}
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError) as error:
        return {'success': False, 'reason': f'レポート読取り失敗: {error}'}
