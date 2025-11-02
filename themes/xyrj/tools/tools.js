/**
 * 2FA 前端脚本（对齐服务器时间 + 精准倒计时 + 显示 29→0）
 * - 统一时间源：客户端时间 + serverOffsetMs（由 HEAD/Date 同步）
 * - 精确对齐每秒与每个 30s 边界（避免 setInterval 漂移）
 * - 数字显示：29..0；到边界生成新码后，显示数字立即回到 29
 */
        
(function() {
  const MAX_REFRESH_COUNT = 3;
  const PERIOD = 30;
  const DIGITS = 6;
  const ALGO = 'SHA1';
  const STORAGE = window.localStorage;

  let refreshCount = 0;
  let serverOffsetMs = 0;
  let timerSecondHandle = null;
  let timerWindowHandle = null;
  let lastNotiAt = 0;

  function nowMs() { return Date.now() + serverOffsetMs; }

  async function syncServerClock() {
    try {
      const t0 = performance.now();
      const res = await fetch(location.href, { method: 'HEAD', cache: 'no-store' });
      const dateStr = res.headers.get('Date');
      if (!dateStr) return;
      const t1 = performance.now();
      const rtt = (t1 - t0);
      const serverEpoch = new Date(dateStr).getTime() + rtt / 2;
      serverOffsetMs = serverEpoch - Date.now();
    } catch (e) { /* 忽略 */ }
  }

  // 关键：把显示值做成 29..0；其余计算维持不变
  function getTickInfo(tsMs) {
    const sec = Math.floor(tsMs / 1000);
    const secondsIntoPeriod = sec % PERIOD;                   // 0..29
    const secondsLeftDisplay = (PERIOD - 1) - secondsIntoPeriod; // 29..0（仅用于显示）
    const nextSecondMs = (sec + 1) * 1000;
    const nextWindowBoundaryMs = (sec - secondsIntoPeriod + PERIOD) * 1000;
    return { sec, secondsIntoPeriod, secondsLeftDisplay, nextSecondMs, nextWindowBoundaryMs };
  }

  function generateTotp(secretBase32, tsMs) {
    const totp = new OTPAuth.TOTP({
      algorithm: ALGO, digits: DIGITS, period: PERIOD,
      secret: OTPAuth.Secret.fromBase32(secretBase32)
    });
    return totp.generate({ timestamp: tsMs });
  }

  function showNotification(message) {
    const now = Date.now();
    if (now - lastNotiAt < 300) return;
    lastNotiAt = now;
    const container = document.getElementById('notification-container');
    const n = document.createElement('div');
    n.className = 'notification';
    n.textContent = message;
    container.appendChild(n);
    void n.offsetWidth;
    n.classList.add('show');
    setTimeout(() => n.remove(), 2600);
  }

  async function copyText(str) {
    if (str === null || str === undefined || str === "") {
        showNotification("内容为空，无需复制。");
        return;
    }
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(str);
      } else {
        const input = document.createElement('input');
        input.value = str;
        document.body.appendChild(input);
        input.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(input);
        if (!ok) throw new Error('execCommand copy failed');
      }
      showNotification("已复制到剪切板！");
    } catch {
      showNotification("无法自动复制，请手动操作！");
    }
  }

  function filterAndValidateSecret(raw) {
    if (!raw) return null;
    let secret = String(raw).replace(/\s+/g, '').toUpperCase();
    const pattern = /^[A-Z2-7]+$/;
    if (secret.length < 16) { showNotification("密钥太短，请重新输入。"); return null; }
    if (secret.length > 128) { showNotification("密钥过长，请重新输入。"); return null; }
    if (!pattern.test(secret)) { showNotification("非正确编码的密钥，请重新输入。"); return null; }
    return secret;
  }

  function prependKeyRecord(secret) {
    const d = new Date();
    const dateString = d.getFullYear() + "." + (d.getMonth() + 1) + "." + d.getDate();
    const newLine = dateString + " - " + secret;
    const $ta = $('#2fa_keys');
    const existing = $ta.val().trim();
    const merged = (newLine + (existing ? "\n" + existing : "")).split('\n');
    const unique = Array.from(new Set(merged));
    const finalText = unique.join('\n');
    $ta.val(finalText);
    STORAGE.setItem('keyAll', finalText);
  }

  // --- START: 修改 - 2FA 定时器控制 ---
  function scheduleSecondTick() {
    if (timerSecondHandle) clearTimeout(timerSecondHandle);
    const t = nowMs();
    const { nextSecondMs } = getTickInfo(t);
    const delay = Math.max(0, nextSecondMs - t);
    timerSecondHandle = setTimeout(onSecondTick, delay);
  }

  function scheduleWindowTick() {
    if (timerWindowHandle) clearTimeout(timerWindowHandle);
    const t = nowMs();
    const { nextWindowBoundaryMs } = getTickInfo(t);
    const delay = Math.max(0, nextWindowBoundaryMs - t);
    timerWindowHandle = setTimeout(onWindowBoundary, delay);
  }

  function stop2FATimers() {
    if (timerSecondHandle) clearTimeout(timerSecondHandle);
    if (timerWindowHandle) clearTimeout(timerWindowHandle);
    timerSecondHandle = null;
    timerWindowHandle = null;
  }

  function start2FATimers() {
      stop2FATimers(); // 先停止任何可能在运行的定时器
      const t = nowMs();
      const { secondsLeftDisplay } = getTickInfo(t);
      $('#timer').text(secondsLeftDisplay);
      $('#timer_js').text(secondsLeftDisplay);
      
      scheduleSecondTick();
      scheduleWindowTick();
  }
  // --- END: 修改 - 2FA 定时器控制 ---

  function onSecondTick() {
    const t = nowMs();
    const { secondsLeftDisplay } = getTickInfo(t);
    // 显示 29..0
    $('#timer').text(secondsLeftDisplay);
    $('#timer_js').text(secondsLeftDisplay);
    scheduleSecondTick();
  }

  function onWindowBoundary() {
    const t = nowMs();

    // 到边界：刷新验证码
    const s1 = filterAndValidateSecret($('#secret-input-js').val());
    const s2 = filterAndValidateSecret($('#secret-input').val()); // s2 相关的PHP逻辑已在原HTML中删除，但保留检查

    if (refreshCount < MAX_REFRESH_COUNT) {
      if (s1) updateJSCode(s1, t, { silent: true });
      else { $("#key_js").text(""); $("#code_js").text(""); }

      if (s2) { /* updatePHPCode(t, { silent: true }); */ } // 原PHP逻辑位置
      else { $("#key").text(""); $("#code").text(""); }

      if (s1 || s2) refreshCount++;
    } else {
      if (s1) { $("#code_js").text("已超时，需要重新点击按钮获取！").css("color", "red"); }
      if (s2) { $("#code").text("已超时，需要重新点击按钮获取！").css("color", "red"); }
    }

    // 关键：刚进入新窗口，显示数字立刻回到 29
    $('#timer').text(29);
    $('#timer_js').text(29);

    scheduleWindowTick();
  }

  function updateJSCode(secret, tsMs, opts = {}) {
    const code = generateTotp(secret, tsMs);
    $("#key_js").text(secret);
    $("#code_js").text(code).css("color", "rgb(50 174 77)");
    STORAGE.setItem("key01", secret);
    if (!opts.silent) showNotification("已成功获取验证码哦~");
    return code;
  }

  // This function is for the 2FA Modal, and uses qrcode.min.js
  function generateQRCode(secretInput) {
    const lastSeven = secretInput.slice(-7);
    const label  = 'Handy tool';
    const issuer = '2fa.run|...' + lastSeven;
    const totp = new OTPAuth.TOTP({
      algorithm: ALGO, digits: DIGITS, period: PERIOD,
      secret: OTPAuth.Secret.fromBase32(secretInput),
      label, issuer
    });
    const uri = totp.toString();
    const qrContainer = document.getElementById('qrcode');
    while (qrContainer.firstChild) qrContainer.removeChild(qrContainer.firstChild);
    new QRCode(qrContainer, { text: uri });
  }

  function openQRFor(inputSelector) {
    let secret = $(inputSelector).val();
    if (!secret) return showNotification("密钥未填写！");
    secret = filterAndValidateSecret(secret);
    if (!secret) return;
    generateQRCode(secret); // This function is for the 2FA modal
    document.getElementById("myModal").style.display = "block";
  }

  $(document).ready(async function() {
    // 方案一：启动时不再禁用输入，立即启动计时器
    $("#secret-input-js").val(STORAGE.getItem("key01") || "");
    $("#2fa_keys").val(STORAGE.getItem("keyAll") || "");

    // 立即启动计时器，使用客户端时间
    start2FATimers();
    
    // 在后台同步服务器时间，完成后计时器会自动校准
    syncServerClock();

    // --- START: 导航切换逻辑 ---
    $('.xyrj-nav li a').on('click', function(e) {
        e.preventDefault();
        var $this = $(this);
        var tool = $this.data('tool');

        if ($this.hasClass('active') || !tool) {
            return; 
        }

        $('.xyrj-nav li a').removeClass('active');
        $this.addClass('active');

        $('.tool-panel').removeClass('active').hide();
        $('#tool-content-' + tool).addClass('active').show();

        if (tool === '2fa') {
            start2FATimers();
        } else {
            stop2FATimers();
        }
    });
    // --- END: 导航切换逻辑 ---

    // --- START: QR 生成器按钮逻辑 (已修改为 API) ---
    $('#generate-qr-btn').on('click', function() {
        // Read values from the correct HTML IDs
        const text = $('#qr-text-input').val();
        const output = $('#qr-output-format').val();
        const errorLevel = $('#qr-correct-level').val();
        const type = $('#qr-type').val();
        const margin = $('#qr-margin').val(); // Correctly reads from the new select
        const size = $('#qr-size').val();     // Correctly reads from the new select
        const $outputImg = $('#qr-code-output-img'); // Get the jQuery object for the img

        if (!text) {
            showNotification('请输入URL或其他文本');
            $outputImg.hide(); // Hide the image
            return;
        }

        // Build the URLSearchParams (as per user's provided code)
        const params = new URLSearchParams({
            data: text,
            output: output,
            error: errorLevel,
            type: type,
            margin: margin,
            size: size,
        });

        const apiUrl = `https://tool.oschina.net/action/qrcode/generate?${params.toString()}`;
        
        // Set the image source and show it
        // Add timestamp to prevent caching
        $outputImg.attr('src', `${apiUrl}&timestamp=${new Date().getTime()}`);
        $outputImg.show(); // Show the image
    });
    // --- END: QR 生成器按钮逻辑 ---
    
    // --- START: 文本处理工具逻辑 (已修改) ---
    const $textIO = $('#text-io');

    // 自动复制包装器
    function processText(newText) {
        $textIO.val(newText);
        if ($('input[name="auto-copy"]:checked').val() === 'yes') {
            copyText(newText);
        }
    }

    // 1. 大小写
    $('#text-btn-upper').on('click', () => processText($textIO.val().toUpperCase()));
    $('#text-btn-lower').on('click', () => processText($textIO.val().toLowerCase()));
    $('#text-btn-cap-words').on('click', () => {
        processText($textIO.val().toLowerCase().replace(/\b\w/g, char => char.toUpperCase()));
    });
    $('#text-btn-lower-words').on('click', () => {
         processText($textIO.val().replace(/\b\w/g, char => char.toLowerCase()));
    });
    $('#text-btn-cap-sentence').on('click', () => {
        processText($textIO.val().toLowerCase().replace(/(^\w|\. \w)/g, char => char.toUpperCase()));
    });
    
    // 标题格
    const smallWords = /^(a|an|and|as|at|but|by|en|for|if|in|of|on|or|the|to|v|via|vs)$/i;
    $('#text-btn-cap-title').on('click', () => {
        let text = $textIO.val().toLowerCase();
        text = text.replace(/\b\w+/g, (word, index) => {
            if (index === 0 || !smallWords.test(word)) {
                return word.charAt(0).toUpperCase() + word.slice(1);
            }
            return word;
        });
        processText(text);
    });

    // 2. 编辑
    $('#text-btn-pinyin').on('click', () => {
        if (typeof pinyinPro === 'undefined') {
            showNotification("错误：pinyin-pro.js 库未加载！");
            return;
        }
        const text = $textIO.val();
        try {
            // 使用 pinyin-pro，不带声调，分隔
            const pinyinResult = pinyinPro.pinyin(text, { toneType: 'none', type: 'string' });
            processText(pinyinResult);
        } catch (e) {
            showNotification("拼音转换失败: " + e.message);
        }
    });
    $('#text-btn-copy').on('click', () => copyText($textIO.val()));
    $('#text-btn-cut').on('click', () => {
        copyText($textIO.val());
        $textIO.val('');
    });
    $('#text-btn-clear').on('click', () => {
        $textIO.val('');
    });

    // 3. 替换
    $('#text-btn-space-to-underscore').on('click', () => processText($textIO.val().replace(/ /g, '_')));
    $('#text-btn-to-camel').on('click', () => {
        processText($textIO.val().toLowerCase().replace(/[\s_]+(\w)/g, (match, char) => char.toUpperCase()));
    });
    $('#text-btn-camel-to-underscore').on('click', () => {
        processText($textIO.val().replace(/([A-Z])/g, '_$1').toLowerCase());
    });
    $('#text-btn-camel-to-space').on('click', () => {
        processText($textIO.val().replace(/([A-Z])/g, ' $1').toLowerCase());
    });
    $('#text-btn-space-to-hyphen').on('click', () => processText($textIO.val().replace(/ /g, '-')));
    $('#text-btn-hyphen-to-underscore').on('click', () => processText($textIO.val().replace(/-/g, '_')));
    $('#text-btn-underscore-to-space').on('click', () => processText($textIO.val().replace(/_/g, ' ')));
    $('#text-btn-underscore-to-dot').on('click', () => processText($textIO.val().replace(/_/g, '.')));
    $('#text-btn-dot-to-underscore').on('click', () => processText($textIO.val().replace(/\./g, '_')));
    
    // 4. 行和空格
    $('#text-btn-space-to-newline').on('click', () => processText($textIO.val().replace(/ /g, '\n')));
    $('#text-btn-newline-to-space').on('click', () => processText($textIO.val().replace(/\n/g, ' ').replace(/\s+/g, ' ')));
    $('#text-btn-clear-lines').on('click', () => processText($textIO.val().replace(/^\s*\d+[\. \t]/gm, '')));
    $('#text-btn-clear-space').on('click', () => processText($textIO.val().replace(/[ \t]/g, '')));
    $('#text-btn-clear-newline').on('click', () => processText($textIO.val().replace(/\n/g, '')));
    // --- END: 文本处理工具逻辑 ---


  }); // $(document).ready 结束

  $(".input-2fa").on("click", function() {
    this.select();
    $(this).css("color", "red");
    if ($(this).val()) showNotification("已全选数据");
  });

  $("#btn-js").on("click", function() {
    let secret = $('#secret-input-js').val();
    secret = filterAndValidateSecret(secret);
    if (!secret) return;
    const code = updateJSCode(secret, nowMs());
    prependKeyRecord(secret);
    copyText(code);
    refreshCount = 0;
  });
  // --- START: 新添加的事件绑定 ---
  
  	  // 绑定 "生成二维码" 按钮
  	  $("#btn-qr-js").on("click", function() {
  	  	  openQRFor('#secret-input-js');
  	  });
  
  	  // 绑定 "清除本地记录" 按钮
  	  $("#btn-del-keys").on("click", function() {
  	  	  if (confirm("确定要清除所有本地记录的2FA密钥吗？此操作不可恢复！")) {
  	  	  	  try {
  	  	  	  	  STORAGE.removeItem('keyAll'); 
  	  	  	  	  $('#2fa_keys').val('');
  	  	  	  	  showNotification("本地记录已清除。");
  	  	  	  } catch (e) {
  	  	  	  	  showNotification("清除失败！", true);
  	  	  	  }
  	  	  }
  	  }); 
  	  // --- END: 新添加的事件绑定 ---

// --- START: Modal 关闭事件 ---    
  	  // 点击 'x' 按钮
  	  $('#myModal .close').on('click', function() {
  	  	  $('#myModal').css('display', 'none');
  	  });
  
    	  // 点击 Modal 外部区域
  	  $('#myModal').on('click', function(event) { 
  	  	  if (event.target == this) {
  	  	  	  $(this).css('display', 'none');
  	  	  }
  	  });
  	    
  	  // --- END: Modal 关闭事件 ---
})(); // 正确关闭 IIFE
