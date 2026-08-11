/**
 * 设置页面管理器
 * 负责设置页面的交互逻辑和UI更新
 */

import { SettingsManager } from './settingsManager';
import { aiService } from '../ai/aiService';
import { PROVIDER_PRESETS, invalidateAIConfigCache } from '../ai/aiConfig';
import { busyboxManager } from '../core/busyboxManager';
import { showConfirm } from '../ui/confirmDialog';
import {
  logger,
} from '../core/logger';
import { reportError } from '../utils/errorHandler';
import { invokeTargetBoundSSH } from '../core/targetBoundSSH';

/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('SettingsPage');

export class SettingsPageManager {
  private settingsManager: SettingsManager;
  private systemFonts: string[] = [];
  private eventsBound = false;

  // 预设提供商（不可删除），与 aiConfig.PROVIDER_PRESETS 保持同源
  private readonly presetProviders = Object.keys(PROVIDER_PRESETS);

  constructor(settingsManager: SettingsManager) {
    this.settingsManager = settingsManager;
  }

  /**
   * 初始化设置页面
   */
  async initialize(): Promise<void> {
    const overlayRoot = document.getElementById('settings-overlay-container');
    if (!overlayRoot) return;

    // 连接诊断不依赖 Tauri invoke，必须在下面的 try 之前绑定——
    // 后面的字体/设置加载一旦抛错就会跳到 catch，再也不会绑定到这里。
    // （诊断日志面板已挪到状态栏「日志」按钮，见 ui/logViewerModal.ts）
    this.bindConnectionDiagnostics();

    try {
      log.debug('初始化设置页面...');

      // 加载系统字体
      await this.loadSystemFonts();

      // 加载设置
      await this.settingsManager.loadSettings();

      // The user may close the overlay while fonts/settings are loading.
      // Do not bind stale global IDs or poison eventsBound for the next open.
      if (!overlayRoot.isConnected) return;

      // 绑定事件监听器
      this.bindEventListeners();

      // 加载设置到表单
      this.loadSettingsToForm();

      // 初始化 busybox 工具面板
      this.initBusyboxPanel();

      log.debug('设置页面初始化完成');
    } catch (error) {
      log.error('设置页面初始化失败:', error);
    }
  }

  /**
   * 加载系统字体
   */
  private async loadSystemFonts(): Promise<void> {
    try {
      log.debug('正在加载系统字体...');

      const { invoke } = await import('@tauri-apps/api/core');
      this.systemFonts = await invoke('get_system_fonts') as string[];

      log.debug('获取到的字体列表:', this.systemFonts.slice(0, 10)); // 显示前10个字体
      log.debug(`总共获取到 ${this.systemFonts.length} 个字体`);

      // 更新字体选择器
      this.updateFontSelector();

      log.debug(`已加载 ${this.systemFonts.length} 个系统字体`);
    } catch (error) {
      log.error('加载系统字体失败:', error);
      // 使用默认字体列表作为后备
      this.systemFonts = this.getDefaultFonts();
      log.debug('使用默认字体列表:', this.systemFonts.slice(0, 10));
      this.updateFontSelector();
    }
  }

  /**
   * 更新字体选择器
   */
  private updateFontSelector(): void {
    const globalFontSelect = document.getElementById('global-font') as HTMLSelectElement;
    if (!globalFontSelect) return;

    // 清空现有选项
    globalFontSelect.innerHTML = '';

    // 添加字体选项
    this.systemFonts.forEach(font => {
      const option = document.createElement('option');
      option.value = font === '系统默认' ? 'system' : font;
      option.textContent = font;

      // 为字体选项添加预览样式
      if (font !== '系统默认') {
        option.style.fontFamily = font;
      }

      globalFontSelect.appendChild(option);
    });
  }

  /**
   * 获取默认字体列表（后备方案）
   */
  private getDefaultFonts(): string[] {
    return [
      '系统默认',
      'Microsoft YaHei',
      '微软雅黑',
      'SimSun',
      '宋体',
      'SimHei',
      '黑体',
      'Arial',
      'Times New Roman',
      'Calibri',
      'Consolas',
      'JetBrains Mono'
    ];
  }

  /**
   * 重置事件绑定标志（设置覆盖层关闭时调用）
   */
  public resetEventBindings(): void {
    this.eventsBound = false;
  }

  /**
   * 绑定事件监听器（同一个 DOM 生命周期内仅绑定一次）
   */
  private bindEventListeners(): void {
    if (this.eventsBound) return;
    this.eventsBound = true;

    // 标签页切换
    document.querySelectorAll('.settings-tab').forEach(tab => {
      tab.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        const tabName = target.getAttribute('data-tab') as 'basic' | 'ai';
        if (tabName) {
          this.switchTab(tabName);
        }
      });
    });

    // 保存设置按钮
    const saveButton = document.getElementById('save-settings');
    if (saveButton) {
      saveButton.addEventListener('click', () => {
        this.saveSettings();
      });
    }

    // 重置设置按钮
    const resetButton = document.getElementById('reset-settings');
    if (resetButton) {
      resetButton.addEventListener('click', () => {
        this.resetSettings();
      });
    }

    // 全局字体变化监听
    const globalFontSelect = document.getElementById('global-font') as HTMLSelectElement;
    if (globalFontSelect) {
      globalFontSelect.addEventListener('change', () => {
        this.previewGlobalFont();
      });
    }

    // 全局字体大小滑块监听
    const globalFontSizeSlider = document.getElementById('global-font-size') as HTMLInputElement;
    const fontSizeValue = document.getElementById('font-size-value');
    if (globalFontSizeSlider && fontSizeValue) {
      globalFontSizeSlider.addEventListener('input', () => {
        const size = globalFontSizeSlider.value;
        fontSizeValue.textContent = `${size}px`;
        this.previewGlobalFontSize(parseInt(size));
      });
    }

    // AI提供商切换监听
    const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;
    if (aiProviderSelect) {
      aiProviderSelect.addEventListener('change', () => {
        this.switchAIProvider();
      });
    }

    // 代理勾选框监听
    const useProxyCheckbox = document.getElementById('ai-use-proxy') as HTMLInputElement;
    if (useProxyCheckbox) {
      useProxyCheckbox.addEventListener('change', () => {
        this.toggleProxySettings();
      });
    }

    // AI连接测试按钮
    const testAIButton = document.getElementById('test-ai-connection');
    if (testAIButton) {
      testAIButton.addEventListener('click', () => {
        this.testAIConnection();
      });
    }

    // 拉取模型列表按钮
    const fetchModelsButton = document.getElementById('ai-fetch-models');
    if (fetchModelsButton) {
      fetchModelsButton.addEventListener('click', () => {
        this.fetchModelList();
      });
    }

    // 新增AI提供商按钮
    const addProviderButton = document.getElementById('add-ai-provider');
    if (addProviderButton) {
      addProviderButton.addEventListener('click', () => {
        this.showAddProviderModal();
      });
    }

    // 删除AI提供商按钮
    const deleteProviderButton = document.getElementById('delete-ai-provider');
    if (deleteProviderButton) {
      deleteProviderButton.addEventListener('click', () => {
        this.deleteCurrentProvider();
      });
    }

    // 新增提供商弹窗相关事件
    const closeModalButton = document.getElementById('close-add-provider-modal');
    const cancelButton = document.getElementById('cancel-add-provider');
    const addProviderForm = document.getElementById('add-provider-form');

    if (closeModalButton) {
      closeModalButton.addEventListener('click', () => {
        this.hideAddProviderModal();
      });
    }

    if (cancelButton) {
      cancelButton.addEventListener('click', () => {
        this.hideAddProviderModal();
      });
    }

    if (addProviderForm) {
      addProviderForm.addEventListener('submit', (e) => {
        e.preventDefault();
        this.saveNewProvider();
      });
    }

    // 点击弹窗背景关闭
    const addProviderModal = document.getElementById('add-provider-modal');
    if (addProviderModal) {
      addProviderModal.addEventListener('click', (e) => {
        if (e.target === addProviderModal) {
          this.hideAddProviderModal();
        }
      });
    }
  }

  /**
   * 切换标签页
   */
  private switchTab(tabName: 'basic' | 'ai'): void {
    // 更新标签页样式（直接操作内联样式）
    document.querySelectorAll('.settings-tab').forEach(tab => {
      const tabElement = tab as HTMLElement;
      const isActive = tab.getAttribute('data-tab') === tabName;

      if (isActive) {
        // 激活状态样式
        tabElement.style.color = 'var(--text-primary)';
        tabElement.style.fontWeight = '500';
        tabElement.style.borderBottom = '2px solid var(--accent-color)';
      } else {
        // 非激活状态样式
        tabElement.style.color = 'var(--text-secondary)';
        tabElement.style.fontWeight = '400';
        tabElement.style.borderBottom = '2px solid transparent';
      }
    });

    // 显示/隐藏面板
    document.querySelectorAll('.settings-panel').forEach(panel => {
      const panelElement = panel as HTMLElement;
      if (panel.id === `${tabName}-settings`) {
        panelElement.style.display = 'block';
      } else {
        panelElement.style.display = 'none';
      }
    });
  }

  /**
   * 加载设置到表单
   */
  private loadSettingsToForm(): void {
    const settings = this.settingsManager.getSettings();

    // 基础设置
    const globalFontSelect = document.getElementById('global-font') as HTMLSelectElement;
    if (globalFontSelect) {
      globalFontSelect.value = settings.ui.globalFont;
    }

    // 字体大小设置
    const globalFontSizeSlider = document.getElementById('global-font-size') as HTMLInputElement;
    const fontSizeValue = document.getElementById('font-size-value');
    if (globalFontSizeSlider && fontSizeValue) {
      const fontSize = settings.ui.globalFontSize || 14;
      globalFontSizeSlider.value = fontSize.toString();
      fontSizeValue.textContent = `${fontSize}px`;
    }

    // AI设置
    // 确保 ai 和 providers 存在
    if (!settings.ai) {
      settings.ai = { providers: {}, currentProvider: 'openai', useProxy: false, proxyType: 'http', proxyUrl: '' };
    }
    if (!settings.ai.providers) {
      settings.ai.providers = {};
    }

    this.updateProviderSelector();

    const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;
    if (aiProviderSelect && settings.ai.currentProvider) {
      aiProviderSelect.value = settings.ai.currentProvider;
    }

    // 加载当前提供商的配置
    this.loadCurrentProviderConfig();

    // 更新删除按钮可见性
    this.updateDeleteButtonVisibility();
  }

  /**
   * 预览全局字体
   */
  private previewGlobalFont(): void {
    const globalFontSelect = document.getElementById('global-font') as HTMLSelectElement;
    if (globalFontSelect) {
      const selectedFont = globalFontSelect.value;
      if (selectedFont && selectedFont !== 'system') {
        // 如果字体名称不包含引号，自动添加
        let fontFamily = selectedFont;
        if (!fontFamily.includes("'") && !fontFamily.includes('"')) {
          fontFamily = `'${fontFamily}', sans-serif`;
        }
        document.documentElement.style.setProperty('--font-family', fontFamily);
      } else {
        document.documentElement.style.removeProperty('--font-family');
      }
    }
  }

  /**
   * 预览全局字体大小
   */
  private previewGlobalFontSize(size: number): void {
    document.documentElement.style.setProperty('--font-size', `${size}px`);
  }

  /**
   * 保存设置
   */
  private async saveSettings(): Promise<void> {
    try {
      log.debug('正在保存设置...');

      const saveButton = document.getElementById('save-settings') as HTMLButtonElement;
      if (saveButton) {
        saveButton.disabled = true;
        saveButton.textContent = '保存中...';
      }

      // 收集表单数据（apiKey 为异步加密落盘，见 collectFormData）
      const formData = await this.collectFormData();

      // 更新设置
      this.settingsManager.updateSettings(formData);

      // 保存设置
      await this.settingsManager.saveSettings();

      // 配置唯一来源是后端 settings 文件；强制 aiConfig 下次重新读取
      invalidateAIConfigCache();

      // 显示成功消息
      this.showMessage('设置保存成功！', 'success');

      // 关闭设置模态框
      setTimeout(() => {
        if ((window as any).hideSettingsOverlay) {
          (window as any).hideSettingsOverlay();
        }
      }, 1000); // 延迟1秒让用户看到成功消息

      log.debug('设置保存成功');
    } catch (error) {
      log.error('保存设置失败:', error);
      this.showMessage('保存设置失败: ' + error, 'error');
    } finally {
      const saveButton = document.getElementById('save-settings') as HTMLButtonElement;
      if (saveButton) {
        saveButton.disabled = false;
        saveButton.textContent = '保存设置';
      }
    }
  }

  /**
   * 收集表单数据（异步：新输入的明文 apiKey 需经后端 encrypt_ai_key 加密）
   */
  private async collectFormData(): Promise<any> {
    const globalFontSelect = document.getElementById('global-font') as HTMLSelectElement;
    const globalFontSizeSlider = document.getElementById('global-font-size') as HTMLInputElement;
    const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;
    const apiKeyInput = document.getElementById('ai-api-key') as HTMLInputElement;
    const modelInput = document.getElementById('ai-model') as HTMLInputElement;
    const baseUrlInput = document.getElementById('ai-base-url') as HTMLInputElement;
    const useProxyCheckbox = document.getElementById('ai-use-proxy') as HTMLInputElement;
    const proxyTypeSelect = document.getElementById('ai-proxy-type') as HTMLSelectElement;
    const proxyUrlInput = document.getElementById('ai-proxy-url') as HTMLInputElement;

    const currentProvider = aiProviderSelect?.value || 'openai';
    const settings = this.settingsManager.getSettings();

    // 确保 ai 和 providers 存在
    if (!settings.ai) {
      settings.ai = { providers: {}, currentProvider: 'openai', useProxy: false, proxyType: 'http', proxyUrl: '' };
    }
    if (!settings.ai.providers) {
      settings.ai.providers = {};
    }

    // 更新当前提供商的配置（原地编辑：保留 name 等未在表单上的字段）
    const updatedProviders = { ...settings.ai.providers };
    if (updatedProviders[currentProvider]) {
      const storedKey = updatedProviders[currentProvider].apiKey || '';
      updatedProviders[currentProvider] = {
        ...updatedProviders[currentProvider],
        apiKey: await this.resolveApiKeyForSave(apiKeyInput?.value?.trim() || '', storedKey),
        model: modelInput?.value || '',
        baseUrl: baseUrlInput?.value || ''
      };
    }

    return {
      ui: {
        globalFont: globalFontSelect?.value || 'system',
        globalFontSize: parseInt(globalFontSizeSlider?.value || '14')
      },
      ai: {
        currentProvider: currentProvider,
        // 代理是全局设置，后端 ai_proxy_* 读取 ai.useProxy/proxyType/proxyUrl
        useProxy: useProxyCheckbox?.checked || false,
        proxyType: (proxyTypeSelect?.value as 'http' | 'https' | 'socks5') || 'http',
        proxyUrl: proxyUrlInput?.value || '',
        providers: updatedProviders
      }
    };
  }

  /**
   * 保存时的 apiKey 处理：
   *  - 输入框留空 → 保留已存值（含 enc:v1: 密文；无 Key 的 ollama/本地 custom 即存空串）
   *  - 输入新值且已是 enc:v1: 密文 → 原样保留（防御性；UI 正常不会回显密文）
   *  - 输入新明文 → 经后端 encrypt_ai_key 加密后落盘，前端不持久化明文
   */
  private async resolveApiKeyForSave(typedKey: string, storedKey: string): Promise<string> {
    if (!typedKey) return storedKey;
    if (typedKey.startsWith('enc:v1:')) return typedKey;
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<string>('encrypt_ai_key', { plaintext: typedKey });
  }

  /**
   * 重置设置
   */
  private async resetSettings(): Promise<void> {
    try {
      if (await showConfirm({ title: '重置设置', message: '确定要重置所有设置到默认值吗？此操作不可撤销。', dangerous: true })) {
        log.debug('正在重置设置...');

        // 重置到默认值
        this.settingsManager.resetToDefaults();

        // 保存设置
        await this.settingsManager.saveSettings();
        invalidateAIConfigCache();
        
        // 重新加载表单
        this.loadSettingsToForm();
        
        // 显示成功消息
        this.showMessage('设置已重置为默认值', 'success');

        log.debug('设置重置成功');
      }
    } catch (error) {
      log.error('重置设置失败:', error);
      this.showMessage('重置设置失败: ' + error, 'error');
    }
  }

  /**
   * 切换AI提供商
   */
  private switchAIProvider(): void {
    this.loadCurrentProviderConfig();
    this.updateDeleteButtonVisibility();
  }

  /**
   * 加载当前提供商配置
   */
  private loadCurrentProviderConfig(): void {
    const settings = this.settingsManager.getSettings();

    // 确保 ai 和 providers 存在
    if (!settings.ai) {
      settings.ai = { providers: {}, currentProvider: 'openai', useProxy: false, proxyType: 'http', proxyUrl: '' };
    }
    if (!settings.ai.providers) {
      settings.ai.providers = {};
    }

    const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;
    const currentProvider = aiProviderSelect?.value || settings.ai.currentProvider;

    const providerConfig = settings.ai.providers[currentProvider];
    if (providerConfig) {
      const apiKeyInput = document.getElementById('ai-api-key') as HTMLInputElement;
      const modelInput = document.getElementById('ai-model') as HTMLInputElement;
      const baseUrlInput = document.getElementById('ai-base-url') as HTMLInputElement;

      if (modelInput) modelInput.value = providerConfig.model;
      if (baseUrlInput) baseUrlInput.value = providerConfig.baseUrl;

      // API Key：enc:v1: 密文绝不回显——输入框留空并用占位符提示，
      // 保存时留空即保留原值（见 collectFormData/resolveApiKeyForSave）
      if (apiKeyInput) {
        const storedKey = providerConfig.apiKey || '';
        if (storedKey.startsWith('enc:v1:')) {
          apiKeyInput.value = '';
          apiKeyInput.placeholder = '已保存，输入新值以更换';
        } else {
          apiKeyInput.value = storedKey;
          const presetName = PROVIDER_PRESETS[currentProvider]?.name;
          apiKeyInput.placeholder = presetName ? `输入您的${presetName} API Key` : '输入您的AI API Key';
        }
      }
    }

    // 代理是全局设置（settings.ai 一级），与当前选中的 provider 无关
    const useProxyCheckbox = document.getElementById('ai-use-proxy') as HTMLInputElement;
    const proxyTypeSelect = document.getElementById('ai-proxy-type') as HTMLSelectElement;
    const proxyUrlInput = document.getElementById('ai-proxy-url') as HTMLInputElement;
    if (useProxyCheckbox) useProxyCheckbox.checked = settings.ai.useProxy || false;
    if (proxyTypeSelect) proxyTypeSelect.value = settings.ai.proxyType || 'http';
    if (proxyUrlInput) proxyUrlInput.value = settings.ai.proxyUrl || '';

    // 更新代理设置显示状态
    this.toggleProxySettings();
  }

  /**
   * 切换代理设置显示/隐藏
   */
  private toggleProxySettings(): void {
    const useProxyCheckbox = document.getElementById('ai-use-proxy') as HTMLInputElement;
    const proxySettingsDiv = document.getElementById('ai-proxy-settings') as HTMLDivElement;

    if (useProxyCheckbox && proxySettingsDiv) {
      proxySettingsDiv.style.display = useProxyCheckbox.checked ? 'block' : 'none';
    }
  }

  /**
   * 测试AI连接
   */
  private async testAIConnection(): Promise<void> {
    const testButton = document.getElementById('test-ai-connection') as HTMLButtonElement;
    const statusSpan = document.getElementById('ai-test-status') as HTMLSpanElement;
    const resultDiv = document.getElementById('ai-test-result') as HTMLDivElement;

    if (!testButton || !statusSpan || !resultDiv) return;

    try {
      // 更新UI状态
      testButton.disabled = true;
      testButton.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="animation: spin 1s linear infinite;">
          <path d="M12,4V2A10,10 0 0,0 2,12H4A8,8 0 0,1 12,4Z"/>
        </svg>
        测试中...
      `;
      statusSpan.textContent = '正在测试连接...';
      statusSpan.style.color = 'var(--text-secondary)';
      resultDiv.style.display = 'none';

      // 获取当前配置
      const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;
      const apiKeyInput = document.getElementById('ai-api-key') as HTMLInputElement;
      const modelInput = document.getElementById('ai-model') as HTMLInputElement;
      const baseUrlInput = document.getElementById('ai-base-url') as HTMLInputElement;

      const provider = aiProviderSelect?.value || 'openai';
      const model = modelInput?.value || '';
      const baseUrl = baseUrlInput?.value || '';

      // 输入框留空时复用已保存的 Key（enc:v1: 密文原样传给后端，由后端解密），
      // 这样测试已保存的 provider 不必重新输入 Key
      const typedKey = apiKeyInput?.value?.trim() || '';
      const storedKey = this.settingsManager.getSettings().ai?.providers?.[provider]?.apiKey || '';
      const apiKey = typedKey || storedKey;

      if (!apiKey && this.resolveProviderType(provider) !== 'ollama') {
        throw new Error('请先输入API Key');
      }

      // 无状态测试：直接用表单值发请求，不触碰已保存配置
      const testResult = await this.performAITest(provider, apiKey, model, baseUrl);

      // 显示成功结果
      statusSpan.textContent = '连接测试成功！';
      statusSpan.style.color = '#22c55e';
      resultDiv.textContent = `AI回复: ${testResult}`;
      resultDiv.style.display = 'block';
      resultDiv.style.borderColor = '#22c55e';

    } catch (error) {
      // 显示错误结果
      statusSpan.textContent = '连接测试失败';
      statusSpan.style.color = '#ef4444';
      resultDiv.textContent = `错误: ${error}`;
      resultDiv.style.display = 'block';
      resultDiv.style.borderColor = '#ef4444';
    } finally {
      // 恢复按钮状态
      testButton.disabled = false;
      testButton.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
        </svg>
        测试连接
      `;
    }
  }

  /**
   * 执行AI连接测试（无状态：不读写任何已保存配置，直接用传入的值发请求）
   */
  private async performAITest(provider: string, apiKey: string, model: string, baseUrl: string): Promise<string> {
    try {
      return await aiService.testConnection({
        providerType: this.resolveProviderType(provider),
        apiKey,
        baseUrl: baseUrl || undefined,
        model: model || undefined,
      });
    } catch (error: any) {
      throw new Error(error.message || 'AI API 连接失败');
    }
  }

  /**
   * 拉取提供商的模型列表，填充模型输入框的 datalist。
   * 与测试连接同样的无状态风格：用表单当前值发请求；Key 输入框留空时
   * 复用已保存的密文（后端自行解密），不必重新输入。
   */
  private async fetchModelList(): Promise<void> {
    const fetchButton = document.getElementById('ai-fetch-models') as HTMLButtonElement;
    const statusDiv = document.getElementById('ai-models-status') as HTMLDivElement;
    const datalist = document.getElementById('ai-model-list') as HTMLDataListElement;
    if (!fetchButton || !statusDiv || !datalist) return;

    const setStatus = (text: string, color: string) => {
      statusDiv.textContent = text;
      statusDiv.style.color = color;
      statusDiv.style.display = text ? 'block' : 'none';
    };

    try {
      fetchButton.disabled = true;
      fetchButton.textContent = '拉取中...';
      setStatus('正在拉取模型列表...', 'var(--text-secondary)');

      const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;
      const apiKeyInput = document.getElementById('ai-api-key') as HTMLInputElement;
      const baseUrlInput = document.getElementById('ai-base-url') as HTMLInputElement;

      const provider = aiProviderSelect?.value || 'openai';
      const typedKey = apiKeyInput?.value?.trim() || '';
      const storedKey = this.settingsManager.getSettings().ai?.providers?.[provider]?.apiKey || '';
      const apiKey = typedKey || storedKey;
      const providerType = this.resolveProviderType(provider);

      if (!apiKey && providerType !== 'ollama') {
        throw new Error('请先输入API Key');
      }

      const models = await aiService.listModels({
        providerType,
        apiKey,
        baseUrl: baseUrlInput?.value?.trim() || undefined,
      });

      // 用拉取到的列表整体替换 datalist 选项（DOM API 赋值，provider 返回的
      // 模型名不会经过 innerHTML）
      datalist.replaceChildren(...models.map((m) => {
        const option = document.createElement('option');
        option.value = m;
        return option;
      }));

      setStatus(`已拉取 ${models.length} 个模型，点击模型输入框选择`, '#22c55e');
    } catch (error) {
      setStatus(`拉取失败: ${(error as Error)?.message ?? error}`, '#ef4444');
      log.warn('拉取模型列表失败:', error);
    } finally {
      fetchButton.disabled = false;
      fetchButton.textContent = '拉取模型';
    }
  }

  /**
   * 显示消息
   */
  private showMessage(message: string, type: 'success' | 'error'): void {
    // 创建消息元素
    const messageDiv = document.createElement('div');
    messageDiv.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 20px;
      border-radius: 6px;
      color: white;
      font-size: 14px;
      z-index: 10000;
      animation: slideIn 0.3s ease-out;
      background: ${type === 'success' ? '#22c55e' : '#ef4444'};
    `;

    // 添加动画样式
    if (!document.getElementById('settings-animations')) {
      const style = document.createElement('style');
      style.id = 'settings-animations';
      style.textContent = `
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }
    messageDiv.textContent = message;

    // 添加动画样式
    const style = document.createElement('style');
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);

    // 添加到页面
    document.body.appendChild(messageDiv);

    // 3秒后自动移除
    setTimeout(() => {
      messageDiv.remove();
      style.remove();
    }, 3000);
  }

  /**
   * 获取字体选项
   */
  getFontOptions(): Array<{ value: string; label: string }> {
    return [
      { value: 'system', label: '系统默认' },
      { value: "'Microsoft YaHei', sans-serif", label: '微软雅黑' },
      { value: "'PingFang SC', sans-serif", label: '苹方' },
      { value: "'Noto Sans CJK SC', sans-serif", label: '思源黑体' },
      { value: "'Source Han Sans SC', sans-serif", label: 'Source Han Sans' },
      { value: "'Consolas', monospace", label: 'Consolas (等宽)' },
      { value: "'JetBrains Mono', monospace", label: 'JetBrains Mono (等宽)' }
    ];
  }

  /**
   * 更新提供商选择器
   */
  private updateProviderSelector(): void {
    const settings = this.settingsManager.getSettings();
    const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;

    if (!aiProviderSelect) return;

    // 保存当前选择
    const currentValue = aiProviderSelect.value;

    // 清空现有选项
    aiProviderSelect.innerHTML = '';

    // 确保 ai 和 providers 存在
    if (!settings.ai) {
      settings.ai = { currentProvider: '', providers: {}, useProxy: false, proxyType: 'http', proxyUrl: '' };
    }
    if (!settings.ai.providers) {
      settings.ai.providers = {};
    }
    if (!settings.ai.currentProvider) {
      settings.ai.currentProvider = '';
    }

    // 添加所有提供商选项
    Object.entries(settings.ai.providers).forEach(([key, provider]) => {
      const option = document.createElement('option');
      option.value = key;
      option.textContent = provider.name;
      aiProviderSelect.appendChild(option);
    });

    // 恢复选择
    if (currentValue && settings.ai.providers[currentValue]) {
      aiProviderSelect.value = currentValue;
    } else {
      aiProviderSelect.value = settings.ai.currentProvider;
    }
  }

  /**
   * 显示新增提供商弹窗
   */
  private showAddProviderModal(): void {
    const modal = document.getElementById('add-provider-modal');
    if (modal) {
      modal.style.display = 'flex';

      // 清空表单
      const form = document.getElementById('add-provider-form') as HTMLFormElement;
      if (form) {
        form.reset();
      }

      // 聚焦到名称输入框
      const nameInput = document.getElementById('new-provider-name') as HTMLInputElement;
      if (nameInput) {
        setTimeout(() => nameInput.focus(), 100);
      }
    }
  }

  /**
   * 隐藏新增提供商弹窗
   */
  private hideAddProviderModal(): void {
    const modal = document.getElementById('add-provider-modal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  /**
   * 保存新提供商
   */
  private async saveNewProvider(): Promise<void> {
    try {
      const nameInput = document.getElementById('new-provider-name') as HTMLInputElement;
      const apiKeyInput = document.getElementById('new-provider-api-key') as HTMLInputElement;
      const modelInput = document.getElementById('new-provider-model') as HTMLInputElement;
      const baseUrlInput = document.getElementById('new-provider-base-url') as HTMLInputElement;

      const name = nameInput?.value?.trim();
      const apiKey = apiKeyInput?.value?.trim() || '';
      const model = modelInput?.value?.trim() || '';
      const baseUrl = baseUrlInput?.value?.trim() || '';

      if (!name) {
        this.showMessage('请输入提供商名称', 'error');
        return;
      }

      // 检查名称是否已存在
      const settings = this.settingsManager.getSettings();
      const existingNames = Object.values(settings.ai.providers).map(p => p.name.toLowerCase());

      if (existingNames.includes(name.toLowerCase())) {
        this.showMessage('提供商名称已存在', 'error');
        return;
      }

      // 生成唯一的key
      const key = this.generateProviderKey(name);

      // 新输入的明文 Key 先经后端加密再落盘（空 Key 的本地 provider 保持空串）
      const encryptedKey = await this.resolveApiKeyForSave(apiKey, '');

      // 「API 格式」radio：决定走 OpenAI 兼容端点还是 Claude /messages 端点
      const formatRadio = document.querySelector<HTMLInputElement>('input[name="new-provider-format"]:checked');
      const apiFormat = formatRadio?.value === 'claude' ? 'claude' as const : 'openai' as const;

      // 添加新提供商
      const newProvider = {
        name: name,
        apiKey: encryptedKey,
        model: model,
        baseUrl: baseUrl,
        type: apiFormat,
        useProxy: false,
        proxyType: 'http' as 'http' | 'https' | 'socks5',
        proxyUrl: ''
      };

      settings.ai.providers[key] = newProvider;
      settings.ai.currentProvider = key;

      // 保存设置
      this.settingsManager.updateSettings(settings);
      await this.settingsManager.saveSettings();
      invalidateAIConfigCache();

      // 更新UI
      this.updateProviderSelector();
      this.loadCurrentProviderConfig();

      // 隐藏弹窗
      this.hideAddProviderModal();

      // 显示成功消息
      this.showMessage(`提供商 "${name}" 添加成功！`, 'success');

    } catch (error) {
      log.error('保存新提供商失败:', error);
      this.showMessage('保存失败: ' + error, 'error');
    }
  }

  /**
   * 生成提供商key
   */
  private generateProviderKey(name: string): string {
    const base = name.toLowerCase()
      .replace(/[^a-z0-9]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '');

    const timestamp = Date.now().toString().slice(-6);
    return `${base}_${timestamp}`;
  }

  /**
   * 判断是否为预设提供商
   */
  private isPresetProvider(key: string): boolean {
    return this.presetProviders.includes(key);
  }

  /**
   * 提供商 key → 归一化类型：预设键（openai/deepseek/claude/ollama/custom）即类型，
   * 其余用户自定义 key 按 custom 处理
   */
  private resolveProviderType(key: string): string {
    return key in PROVIDER_PRESETS ? key : 'custom';
  }

  /**
   * 更新删除按钮的可见性
   */
  private updateDeleteButtonVisibility(): void {
    const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;
    const deleteButton = document.getElementById('delete-ai-provider') as HTMLButtonElement;

    if (!aiProviderSelect || !deleteButton) return;

    const currentProvider = aiProviderSelect.value;
    const isCustom = !this.isPresetProvider(currentProvider);

    if (isCustom) {
      deleteButton.style.display = 'flex';
    } else {
      deleteButton.style.display = 'none';
    }
  }

  /**
   * 删除当前提供商
   */
  private async deleteCurrentProvider(): Promise<void> {
    try {
      const aiProviderSelect = document.getElementById('ai-provider') as HTMLSelectElement;
      if (!aiProviderSelect) return;

      const currentProvider = aiProviderSelect.value;

      // 检查是否为预设提供商
      if (this.isPresetProvider(currentProvider)) {
        this.showMessage('预设提供商不能删除', 'error');
        return;
      }

      const settings = this.settingsManager.getSettings();
      const providerName = settings.ai.providers[currentProvider]?.name || currentProvider;

      // 确认删除
      if (!(await showConfirm({ title: '删除提供商', message: `确定要删除提供商 "${providerName}" 吗？此操作不可撤销。`, dangerous: true }))) {
        return;
      }

      // 删除提供商
      delete settings.ai.providers[currentProvider];

      // 切换到默认提供商
      settings.ai.currentProvider = 'openai';

      // 保存设置
      this.settingsManager.updateSettings(settings);
      await this.settingsManager.saveSettings();
      invalidateAIConfigCache();

      // 更新UI
      this.updateProviderSelector();
      this.loadCurrentProviderConfig();
      this.updateDeleteButtonVisibility();

      // 显示成功消息
      this.showMessage(`提供商 "${providerName}" 已删除`, 'success');

    } catch (error) {
      log.error('删除提供商失败:', error);
      this.showMessage('删除失败: ' + error, 'error');
    }
  }

  // ──── Busybox 工具面板 ────

  private initBusyboxPanel(): void {
    const statusEl = document.getElementById('settings-bb-status');
    const pathEl = document.getElementById('settings-bb-path');
    const logEl = document.getElementById('settings-bb-log');

    const showLog = (text: string) => {
      if (logEl) { logEl.style.display = 'block'; logEl.textContent = text; }
    };

    // 检测状态
    busyboxManager.detect().then(({ status, path }) => {
      if (statusEl) {
        const labels: Record<string, string> = {
          'enabled': '已启用',
          'installed': '已安装 (未启用)',
          'not-installed': '未安装',
          'unknown': '未知',
        };
        statusEl.textContent = '状态: ' + (labels[status] || status);
        statusEl.style.color = status === 'enabled' ? '#22c55e' : status === 'installed' ? '#3b82f6' : 'var(--text-secondary)';
      }
      if (pathEl && path) pathEl.textContent = path;
    }).catch((e) => {
      if (statusEl) {
        statusEl.textContent = '状态: 检测失败';
        statusEl.style.color = '#ef4444';
      }
      showLog(String(e));
    });

    // 上传按钮
    (window as any).__settingsBusyboxUpload = async () => {
      if (statusEl) statusEl.textContent = '状态: 上传中...';
      try {
        const log = await busyboxManager.uploadFromLocal();
        showLog(log);
        if (statusEl) { statusEl.textContent = '状态: 已安装'; statusEl.style.color = '#3b82f6'; }
        if (pathEl) pathEl.textContent = busyboxManager.getPath();
        window.showNotification?.('busybox 上传成功', 'success');
      } catch (e: any) {
        showLog(String(e));
        if (statusEl) { statusEl.textContent = '状态: 上传失败'; statusEl.style.color = '#ef4444'; }
        if (e?.message?.includes('未选择文件')) {
          // 用户取消了文件选择，静默处理
          if (statusEl) statusEl.textContent = '状态: 未安装';
        } else {
          window.showNotification?.(`上传失败: ${e}`, 'error');
        }
      }
    };

    // 启用按钮
    (window as any).__settingsBusyboxEnable = async () => {
      try {
        await busyboxManager.enable();
        if (statusEl) { statusEl.textContent = '状态: 已启用'; statusEl.style.color = '#22c55e'; }
        window.showNotification?.('busybox 可信模式已启用', 'success');
      } catch (e) {
        window.showNotification?.(`启用失败: ${e}`, 'error');
      }
    };

    // 禁用按钮
    (window as any).__settingsBusyboxDisable = async () => {
      try {
        await busyboxManager.disable();
        if (statusEl) { statusEl.textContent = '状态: 已安装 (未启用)'; statusEl.style.color = '#3b82f6'; }
        window.showNotification?.('busybox 模式已禁用', 'info');
      } catch (e) {
        window.showNotification?.(`禁用失败: ${e}`, 'error');
      }
    };
  }

  /**
   * 连接诊断面板。
   *
   * test_ssh_performance / diagnose_shell_performance 两个 Rust command 早就实现
   * 并注册在 invoke_handler 里，却一直没有任何前端入口。赛场上靶机响应慢时，
   * 判断是网络/SSH 通道问题还是 shell 登录脚本被拖慢（或被塞了后门），这两条最直接。
   */
  private bindConnectionDiagnostics(): void {
    const show = (text: string) => {
      const el = document.getElementById('conn-diag-output');
      if (!el) return;
      el.style.display = 'block';
      el.textContent = text;
    };

    const run = async (command: 'test_ssh_performance' | 'diagnose_shell_performance', label: string) => {
      show(`${label} 执行中…`);
      try {
        const out = await invokeTargetBoundSSH<string>(command);
        show(out || '(无输出)');
      } catch (e) {
        show(`${label}失败：${e}`);
        reportError(e, { module: 'Settings', action: label, silent: true });
      }
    };

    (window as any).__diagSshPerf = () => void run('test_ssh_performance', '命令往返耗时测试');
    (window as any).__diagShellPerf = () => void run('diagnose_shell_performance', 'Shell 启动诊断');
  }
}
