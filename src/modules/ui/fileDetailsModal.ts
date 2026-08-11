/**
 * 文件详情模态框
 * 显示文件的详细信息，包括基础信息、时间戳等
 */

import { createIconHTML, statusIcon } from './iconMapping';
import { invokeTargetBoundSSH } from '../core/targetBoundSSH';

export class FileDetailsModal {
  private modal: HTMLElement | null = null;
  private isVisible: boolean = false;
  private currentFilePath: string = '';

  constructor() {
    this.createModal();
    this.bindEvents();
  }

  private createModal(): void {
    const modalHTML = `
      <div id="file-details-modal" class="modal-overlay" style="
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: none;
        z-index: 10000;
        backdrop-filter: blur(4px);
      ">
        <div class="modal-content" style="
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          width: 600px;
          max-width: 90vw;
          background: var(--bg-primary);
          border-radius: var(--border-radius-lg);
          border: 1px solid var(--border-color);
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
          overflow: hidden;
        ">
          <!-- 模态头部 -->
          <div class="modal-header" style="
            padding: var(--spacing-md);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-secondary);
          ">
            <h3 style="
              margin: 0;
              color: var(--text-primary);
              font-size: 16px;
              font-weight: 600;
              display: flex;
              align-items: center;
              gap: var(--spacing-sm);
            ">
              <span style="font-size: 18px;">${createIconHTML('📊', { size: 18 })}</span>
              文件详细信息
            </h3>
            <button id="file-details-close-btn" style="
              background: none;
              border: none;
              color: var(--text-secondary);
              font-size: 18px;
              cursor: pointer;
              padding: 4px;
              border-radius: var(--border-radius-sm);
              transition: var(--transition);
            ">
              ✕
            </button>
          </div>

          <!-- 模态内容 -->
          <div class="modal-body" style="
            padding: var(--spacing-lg);
            max-height: 70vh;
            overflow-y: auto;
          ">
            <!-- 文件基本信息 -->
            <div class="info-section" style="margin-bottom: var(--spacing-lg);">
              <h4 style="
                margin: 0 0 var(--spacing-md) 0;
                color: var(--text-primary);
                font-size: 14px;
                font-weight: 600;
                border-bottom: 1px solid var(--border-color);
                padding-bottom: var(--spacing-sm);
              ">基本信息</h4>
              <div class="info-grid" style="
                display: grid;
                grid-template-columns: 120px 1fr;
                gap: var(--spacing-sm);
                font-size: 13px;
              ">
                <div style="color: var(--text-secondary);">文件名:</div>
                <div id="file-details-name" style="color: var(--text-primary); word-break: break-all;"></div>
                
                <div style="color: var(--text-secondary);">完整路径:</div>
                <div id="file-details-path" style="color: var(--text-primary); word-break: break-all; font-family: var(--font-mono);"></div>
                
                <div style="color: var(--text-secondary);">文件类型:</div>
                <div id="file-details-type" style="color: var(--text-primary);"></div>
                
                <div style="color: var(--text-secondary);">文件大小:</div>
                <div id="file-details-size" style="color: var(--text-primary);"></div>
                
                <div style="color: var(--text-secondary);">权限:</div>
                <div id="file-details-permissions" style="color: var(--text-primary); font-family: var(--font-mono);"></div>
                
                <div style="color: var(--text-secondary);">所有者:</div>
                <div id="file-details-owner" style="color: var(--text-primary);"></div>
                
                <div style="color: var(--text-secondary);">用户组:</div>
                <div id="file-details-group" style="color: var(--text-primary);"></div>
              </div>
            </div>

            <!-- 时间信息 -->
            <div class="info-section" style="margin-bottom: var(--spacing-lg);">
              <h4 style="
                margin: 0 0 var(--spacing-md) 0;
                color: var(--text-primary);
                font-size: 14px;
                font-weight: 600;
                border-bottom: 1px solid var(--border-color);
                padding-bottom: var(--spacing-sm);
              ">时间信息</h4>
              <div class="info-grid" style="
                display: grid;
                grid-template-columns: 120px 1fr;
                gap: var(--spacing-sm);
                font-size: 13px;
              ">
                <div style="color: var(--text-secondary);">创建时间:</div>
                <div id="file-details-created" style="color: var(--text-primary);"></div>
                
                <div style="color: var(--text-secondary);">修改时间:</div>
                <div id="file-details-modified" style="color: var(--text-primary);"></div>
                
                <div style="color: var(--text-secondary);">访问时间:</div>
                <div id="file-details-accessed" style="color: var(--text-primary);"></div>
              </div>
            </div>

            <!-- 加载状态 -->
            <div id="file-details-loading" style="
              text-align: center;
              padding: var(--spacing-xl);
              color: var(--text-secondary);
              display: none;
            ">
              <div style="font-size: 24px; margin-bottom: var(--spacing-sm);">${createIconHTML('🔄', { size: 24 })}</div>
              <div>正在获取文件详细信息...</div>
            </div>

            <!-- 错误状态 -->
            <div id="file-details-error" style="
              text-align: center;
              padding: var(--spacing-xl);
              color: var(--error-color);
              display: none;
            ">
              <div style="font-size: 24px; margin-bottom: var(--spacing-sm);">${statusIcon('error', { size: 24 })}</div>
              <div id="file-details-error-message">获取文件信息失败</div>
            </div>
          </div>

          <!-- 模态底部 -->
          <div class="modal-footer" style="
            padding: var(--spacing-md);
            border-top: 1px solid var(--border-color);
            background: var(--bg-secondary);
            display: flex;
            justify-content: flex-end;
            gap: var(--spacing-sm);
          ">
            <button id="file-details-refresh-btn" class="modern-btn secondary" style="
              padding: var(--spacing-sm) var(--spacing-md);
              font-size: 12px;
            ">
              ${createIconHTML('🔄', { size: 14 })} 刷新
            </button>
            <button id="file-details-close-footer-btn" class="modern-btn secondary" style="
              padding: var(--spacing-sm) var(--spacing-md);
              font-size: 12px;
            ">
              关闭
            </button>
          </div>
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHTML);
    this.modal = document.getElementById('file-details-modal');
  }

  private bindEvents(): void {
    // 关闭按钮
    document.getElementById('file-details-close-btn')?.addEventListener('click', () => {
      this.hide();
    });

    document.getElementById('file-details-close-footer-btn')?.addEventListener('click', () => {
      this.hide();
    });

    // 刷新按钮
    document.getElementById('file-details-refresh-btn')?.addEventListener('click', () => {
      if (this.currentFilePath) {
        this.loadFileDetails(this.currentFilePath);
      }
    });

    // 点击遮罩关闭
    this.modal?.addEventListener('click', (e) => {
      if (e.target === this.modal) {
        this.hide();
      }
    });

    // ESC键关闭
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.isVisible) {
        this.hide();
      }
    });
  }

  public async show(filePath: string): Promise<void> {
    if (!this.modal) return;

    this.currentFilePath = filePath;
    this.isVisible = true;
    this.modal.style.display = 'block';

    // 加载文件详细信息
    await this.loadFileDetails(filePath);
  }

  public hide(): void {
    if (!this.modal) return;
    
    this.modal.style.display = 'none';
    this.isVisible = false;
    this.currentFilePath = '';
  }

  private async loadFileDetails(filePath: string): Promise<void> {
    // 显示加载状态
    this.showLoading();

    try {
      // 调用后端API获取文件详细信息
      const details = await invokeTargetBoundSSH<any>('sftp_get_file_details', {
        path: filePath
      });

      console.log('获取到文件详细信息:', details);
      this.displayFileDetails(details);
      
    } catch (error) {
      console.error('获取文件详细信息失败:', error);
      this.showError(`获取文件信息失败: ${error}`);
    }
  }

  private showLoading(): void {
    // 隐藏内容区域，显示加载状态
    const sections = document.querySelectorAll('.info-section');
    sections.forEach(section => (section as HTMLElement).style.display = 'none');
    
    const loading = document.getElementById('file-details-loading');
    const error = document.getElementById('file-details-error');
    
    if (loading) loading.style.display = 'block';
    if (error) error.style.display = 'none';
  }

  private showError(message: string): void {
    // 隐藏加载状态，显示错误
    const loading = document.getElementById('file-details-loading');
    const error = document.getElementById('file-details-error');
    const errorMessage = document.getElementById('file-details-error-message');
    
    if (loading) loading.style.display = 'none';
    if (error) error.style.display = 'block';
    if (errorMessage) errorMessage.textContent = message;
  }

  private displayFileDetails(details: any): void {
    // 隐藏加载和错误状态，显示内容
    const sections = document.querySelectorAll('.info-section');
    sections.forEach(section => (section as HTMLElement).style.display = 'block');
    
    const loading = document.getElementById('file-details-loading');
    const error = document.getElementById('file-details-error');
    
    if (loading) loading.style.display = 'none';
    if (error) error.style.display = 'none';

    // 填充基本信息
    this.setElementText('file-details-name', details.name || '未知');
    this.setElementText('file-details-path', details.path || '未知');
    this.setElementHTML('file-details-type', this.getFileTypeDisplay(details.file_type));
    this.setElementText('file-details-size', this.formatFileSize(details.size));
    this.setElementText('file-details-permissions', this.formatPermissions(details.permissions));
    this.setElementText('file-details-owner', details.owner || '未知');
    this.setElementText('file-details-group', details.group || '未知');

    // 填充时间信息
    this.setElementText('file-details-created', this.formatDateTime(details.created));
    this.setElementText('file-details-modified', this.formatDateTime(details.modified));
    this.setElementText('file-details-accessed', this.formatDateTime(details.accessed));
  }

  private setElementText(id: string, text: string): void {
    const element = document.getElementById(id);
    if (element) {
      element.textContent = text;
    }
  }

  private setElementHTML(id: string, html: string): void {
    const element = document.getElementById(id);
    if (element) {
      element.innerHTML = html;
    }
  }

  private getFileTypeDisplay(fileType: string): string {
    const typeMap: { [key: string]: string } = {
      'file': `${createIconHTML('📄', { size: 14 })} 普通文件`,
      'directory': `${createIconHTML('📁', { size: 14 })} 目录`,
      'symlink': `${createIconHTML('🔗', { size: 14 })} 符号链接`,
      'block': `${createIconHTML('💽', { size: 14 })} 块设备`,
      'char': `${createIconHTML('🐚', { size: 14 })} 字符设备`,
      'fifo': `${createIconHTML('📡', { size: 14 })} 命名管道`,
      'socket': `${createIconHTML('🔌', { size: 14 })} 套接字`
    };
    return typeMap[fileType] || `${fileType}`;
  }

  private formatFileSize(size: number): string {
    if (size === 0) return '0 B';
    if (size < 0) return '未知';
    
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(size) / Math.log(1024));
    return `${(size / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  }

  private formatPermissions(permissions: string): string {
    if (!permissions) return '未知';
    
    // 如果是数字权限，转换为符号权限
    if (/^\d+$/.test(permissions)) {
      return this.octalToSymbolic(permissions);
    }
    
    return permissions;
  }

  private octalToSymbolic(octal: string): string {
    const perms = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx'];
    const digits = octal.padStart(3, '0').slice(-3);
    return digits.split('').map(d => perms[parseInt(d)]).join('');
  }

  private formatDateTime(timestamp: string | null): string {
    if (!timestamp) return '未知';
    
    try {
      const date = new Date(timestamp);
      return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch (e) {
      return timestamp;
    }
  }
}
