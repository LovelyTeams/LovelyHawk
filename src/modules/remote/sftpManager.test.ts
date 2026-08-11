/**
 * 回归测试：SFTP 列表的**索引一致性**
 *
 * 表格渲染时按展示顺序给每一行发下标（data-file-index / 右键菜单 / 双击导航），
 * 之后右键菜单再拿这个下标去取文件并执行删除、重命名等破坏性操作。
 * 因此下面这条不变量一旦破掉，用户删掉的就是**另一个文件**：
 *
 *     getFileByIndex(i) === getCurrentFiles()[i]      对任意 i、任意排序方式
 *
 * 曾经的 bug：fileList 里存的是抓取时排好序的副本，setSortMode 只改 sortMode
 * 不重排，而渲染按重新排序的结果编号 —— 点过排序表头后两者就错位了。
 * 更隐蔽的是详情面板用的是 getCurrentFiles()（对的），右键菜单用
 * getFileByIndex()（错的），于是面板显示 A、删除的却是 B。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { activeTargetContext } from '../core/targetContext';
import { SftpManager, type SftpFileInfo } from './sftpManager';

type SortMode = 'name-asc' | 'name-desc' | 'size-asc' | 'size-desc' | 'modified-asc' | 'modified-desc';
const ALL_SORT_MODES: SortMode[] = [
  'name-asc', 'name-desc', 'size-asc', 'size-desc', 'modified-asc', 'modified-desc',
];

function file(name: string, size: number, type: 'file' | 'directory', modified: string): SftpFileInfo {
  return {
    name,
    size,
    file_type: type,
    permissions: '644',
    owner: '0',
    group: '0',
    modified,
    path: `/tmp/${name}`,
  };
}

/**
 * 刻意做成"服务端返回顺序"——既不是按名字排的，也不是目录优先，
 * 这正是 sftp_list_files 的真实形态。
 */
const REMOTE_ORDER: SftpFileInfo[] = [
  file('zebra.log', 900, 'file', '2026-01-05T10:00:00Z'),
  file('etc', 4096, 'directory', '2026-03-01T10:00:00Z'),
  file('alpha.txt', 100, 'file', '2026-02-01T10:00:00Z'),
  file('bin', 4096, 'directory', '2026-01-01T10:00:00Z'),
  file('middle.sh', 500, 'file', '2026-04-01T10:00:00Z'),
];

describe('SftpManager 索引一致性', () => {
  let mgr: SftpManager;

  beforeEach(() => {
    activeTargetContext.clear();
    mgr = new SftpManager();
    // fileList 是私有的：直接注入以避开 Tauri invoke
    (mgr as unknown as { fileList: SftpFileInfo[] }).fileList = [...REMOTE_ORDER];
    (mgr as unknown as { sortedCache: unknown }).sortedCache = null;
  });

  afterEach(() => activeTargetContext.clear());

  it('默认排序下，右键菜单取到的文件与表格渲染的行一致', () => {
    const shown = mgr.getCurrentFiles();
    shown.forEach((expected, i) => {
      expect(mgr.getFileByIndex(i)?.name).toBe(expected.name);
    });
  });

  it('切换任一排序方式后仍然一致（这里曾经会删错文件）', () => {
    for (const mode of ALL_SORT_MODES) {
      mgr.setSortMode(mode);
      const shown = mgr.getCurrentFiles();
      expect(shown.length).toBe(REMOTE_ORDER.length);
      shown.forEach((expected, i) => {
        expect(
          mgr.getFileByIndex(i)?.name,
          `排序方式 ${mode} 下第 ${i} 行错位`,
        ).toBe(expected.name);
      });
    }
  });

  it('排序确实改变了展示顺序（否则上面的用例是空转）', () => {
    mgr.setSortMode('name-asc');
    const asc = mgr.getCurrentFiles().map((f) => f.name);
    mgr.setSortMode('name-desc');
    const desc = mgr.getCurrentFiles().map((f) => f.name);
    expect(asc).not.toEqual(desc);

    // 展示顺序也必须与服务端返回顺序不同，否则测不出错位
    expect(asc).not.toEqual(REMOTE_ORDER.map((f) => f.name));
  });

  it('目录始终排在文件前面', () => {
    for (const mode of ALL_SORT_MODES) {
      mgr.setSortMode(mode);
      const types = mgr.getCurrentFiles().map((f) => f.file_type);
      const lastDir = types.lastIndexOf('directory');
      const firstFile = types.indexOf('file');
      if (lastDir !== -1 && firstFile !== -1) {
        expect(lastDir, `排序方式 ${mode} 下目录没有优先`).toBeLessThan(firstFile);
      }
    }
  });

  it('越界下标返回 null，不抛异常', () => {
    expect(mgr.getFileByIndex(-1)).toBeNull();
    expect(mgr.getFileByIndex(REMOTE_ORDER.length)).toBeNull();
    expect(mgr.getFileByIndex(9999)).toBeNull();
  });

  it('SSH 会话变化时清空上一目标的路径、列表和 UID 缓存', () => {
    const target = {
      sessionId: 'session-a', hostKeyFingerprint: 'SHA256:a', host: '10.0.0.1', port: 22, username: 'root',
    };
    activeTargetContext.activate(target);
    expect(mgr.getCurrentFiles()).toEqual([]);

    (mgr as unknown as { currentPath: string }).currentPath = '/var/www';
    (mgr as unknown as { fileList: SftpFileInfo[] }).fileList = [...REMOTE_ORDER];
    (mgr as unknown as { uidNameCache: Record<string, string> }).uidNameCache = { '1000': 'alice' };
    (mgr as unknown as { uidCacheLoaded: boolean }).uidCacheLoaded = true;

    activeTargetContext.activate({ ...target, sessionId: 'session-b' });

    expect(mgr.getCurrentPath()).toBe('/');
    expect(mgr.getCurrentFiles()).toEqual([]);
    expect(mgr.resolveOwnerName('1000')).toBe('user');
  });
});
