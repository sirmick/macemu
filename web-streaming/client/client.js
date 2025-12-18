/**
 * Basilisk II Web Client
 *
 * Handles WebSocket communication, rendering, and input for the
 * web-based Mac emulator streaming client.
 *
 * Uses WebGL for efficient GPU-accelerated frame rendering.
 */

// Message types (must match server)
const MSG_FRAME = 0x01;
const MSG_AUDIO = 0x02;
const MSG_INPUT = 0x03;
const MSG_CONFIG = 0x04;
const MSG_STATUS = 0x05;

// Input event types
const INPUT_MOUSE_MOVE = 0x01;
const INPUT_MOUSE_DOWN = 0x02;
const INPUT_MOUSE_UP = 0x03;
const INPUT_KEY_DOWN = 0x04;
const INPUT_KEY_UP = 0x05;

// WebGL shaders
const VERTEX_SHADER = `
    attribute vec2 a_position;
    attribute vec2 a_texCoord;
    varying vec2 v_texCoord;
    void main() {
        gl_Position = vec4(a_position, 0.0, 1.0);
        v_texCoord = a_texCoord;
    }
`;

const FRAGMENT_SHADER = `
    precision mediump float;
    uniform sampler2D u_texture;
    varying vec2 v_texCoord;
    void main() {
        gl_FragColor = texture2D(u_texture, v_texCoord);
    }
`;

class WebGLRenderer {
    constructor(canvas) {
        this.canvas = canvas;
        this.gl = null;
        this.program = null;
        this.texture = null;
        this.textureWidth = 0;
        this.textureHeight = 0;

        this.init();
    }

    init() {
        // Try to get WebGL context
        this.gl = this.canvas.getContext('webgl', {
            alpha: false,
            antialias: false,
            depth: false,
            preserveDrawingBuffer: false,
            powerPreference: 'high-performance'
        });

        if (!this.gl) {
            console.warn('WebGL not available, falling back to 2D canvas');
            return false;
        }

        const gl = this.gl;

        // Compile shaders
        const vertShader = this.compileShader(gl.VERTEX_SHADER, VERTEX_SHADER);
        const fragShader = this.compileShader(gl.FRAGMENT_SHADER, FRAGMENT_SHADER);

        if (!vertShader || !fragShader) {
            console.error('Failed to compile shaders');
            return false;
        }

        // Create program
        this.program = gl.createProgram();
        gl.attachShader(this.program, vertShader);
        gl.attachShader(this.program, fragShader);
        gl.linkProgram(this.program);

        if (!gl.getProgramParameter(this.program, gl.LINK_STATUS)) {
            console.error('Shader program link failed:', gl.getProgramInfoLog(this.program));
            return false;
        }

        gl.useProgram(this.program);

        // Set up geometry - fullscreen quad
        const positions = new Float32Array([
            -1, -1,   1, -1,   -1, 1,
            -1,  1,   1, -1,    1, 1
        ]);

        // Texture coordinates (flip Y for correct orientation)
        const texCoords = new Float32Array([
            0, 1,   1, 1,   0, 0,
            0, 0,   1, 1,   1, 0
        ]);

        // Position buffer
        const posBuffer = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, posBuffer);
        gl.bufferData(gl.ARRAY_BUFFER, positions, gl.STATIC_DRAW);

        const posLoc = gl.getAttribLocation(this.program, 'a_position');
        gl.enableVertexAttribArray(posLoc);
        gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

        // Texture coordinate buffer
        const texBuffer = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, texBuffer);
        gl.bufferData(gl.ARRAY_BUFFER, texCoords, gl.STATIC_DRAW);

        const texLoc = gl.getAttribLocation(this.program, 'a_texCoord');
        gl.enableVertexAttribArray(texLoc);
        gl.vertexAttribPointer(texLoc, 2, gl.FLOAT, false, 0, 0);

        // Create texture
        this.texture = gl.createTexture();
        gl.bindTexture(gl.TEXTURE_2D, this.texture);

        // Set texture parameters for pixel-perfect rendering
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);

        // Set texture uniform
        const texUniform = gl.getUniformLocation(this.program, 'u_texture');
        gl.uniform1i(texUniform, 0);

        console.log('WebGL renderer initialized');
        return true;
    }

    compileShader(type, source) {
        const gl = this.gl;
        const shader = gl.createShader(type);
        gl.shaderSource(shader, source);
        gl.compileShader(shader);

        if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
            console.error('Shader compile error:', gl.getShaderInfoLog(shader));
            gl.deleteShader(shader);
            return null;
        }

        return shader;
    }

    updateTexture(pixelData, width, height) {
        const gl = this.gl;
        if (!gl) return;

        gl.bindTexture(gl.TEXTURE_2D, this.texture);

        // Check if we need to reallocate the texture
        if (width !== this.textureWidth || height !== this.textureHeight) {
            // Allocate new texture
            gl.texImage2D(
                gl.TEXTURE_2D, 0, gl.RGBA,
                width, height, 0,
                gl.RGBA, gl.UNSIGNED_BYTE, pixelData
            );
            this.textureWidth = width;
            this.textureHeight = height;
            console.log(`WebGL texture allocated: ${width}x${height}`);
        } else {
            // Update existing texture (faster)
            gl.texSubImage2D(
                gl.TEXTURE_2D, 0, 0, 0,
                width, height,
                gl.RGBA, gl.UNSIGNED_BYTE, pixelData
            );
        }
    }

    render() {
        const gl = this.gl;
        if (!gl) return;

        gl.viewport(0, 0, this.canvas.width, this.canvas.height);
        gl.drawArrays(gl.TRIANGLES, 0, 6);
    }

    resize(width, height) {
        this.canvas.width = width;
        this.canvas.height = height;

        // Set CSS size for proper display
        this.canvas.style.width = width + 'px';
        this.canvas.style.height = height + 'px';
    }

    isAvailable() {
        return this.gl !== null;
    }
}

class BasiliskClient {
    constructor() {
        this.ws = null;
        this.canvas = document.getElementById('display');
        this.connected = false;

        // Initialize WebGL renderer
        this.renderer = new WebGLRenderer(this.canvas);

        // Fallback to 2D canvas if WebGL not available
        if (!this.renderer.isAvailable()) {
            this.ctx = this.canvas.getContext('2d');
            this.useWebGL = false;
            console.log('Using Canvas 2D fallback');
        } else {
            this.ctx = null;
            this.useWebGL = true;
            console.log('Using WebGL renderer');
        }

        // Performance tracking
        this.frameCount = 0;
        this.lastFpsTime = performance.now();
        this.fps = 0;
        this.latency = 0;
        this.lastPingTime = 0;

        // Bandwidth tracking
        this.bytesReceived = 0;
        this.lastBandwidthTime = performance.now();
        this.bandwidth = 0;  // bytes per second

        // Audio context (created on first user interaction)
        this.audioContext = null;
        this.audioQueue = [];
        this.nextAudioTime = 0;

        // Server URL (default to same host on port 8090)
        // Can be overridden via URL param: ?server=ws://host:port
        const params = new URLSearchParams(window.location.search);
        this.serverUrl = params.get('server') || `ws://${window.location.hostname}:8090`;

        // Bind methods
        this.onMessage = this.onMessage.bind(this);
        this.onOpen = this.onOpen.bind(this);
        this.onClose = this.onClose.bind(this);
        this.onError = this.onError.bind(this);

        // Set up input handlers
        this.setupInputHandlers();

        // FPS counter update
        setInterval(() => this.updateFps(), 1000);

        // Latency ping
        setInterval(() => this.sendPing(), 5000);
    }

    connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return;
        }

        this.updateOverlay('Connecting...', true);

        try {
            this.ws = new WebSocket(this.serverUrl, 'basilisk-protocol');
            this.ws.binaryType = 'arraybuffer';

            this.ws.onopen = this.onOpen;
            this.ws.onclose = this.onClose;
            this.ws.onerror = this.onError;
            this.ws.onmessage = this.onMessage;
        } catch (e) {
            console.error('WebSocket connection failed:', e);
            this.updateOverlay('Connection failed', false);
        }
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        this.connected = false;
        this.updateStatus(false);
        this.updateOverlay('Disconnected', false);
    }

    onOpen() {
        console.log('Connected to server');
        this.connected = true;
        this.updateStatus(true);
        this.hideOverlay();

        // Initialize audio on connection
        this.initAudio();

        // Request initial frame
        this.sendPing();
    }

    onClose() {
        console.log('Disconnected from server');
        this.connected = false;
        this.updateStatus(false);
        this.updateOverlay('Disconnected - Click to reconnect', false);
    }

    onError(error) {
        console.error('WebSocket error:', error);
        this.updateOverlay('Connection error', false);
    }

    onMessage(event) {
        if (!(event.data instanceof ArrayBuffer)) {
            // JSON message
            try {
                const data = JSON.parse(event.data);
                this.handleJsonMessage(data);
            } catch (e) {
                console.error('Failed to parse JSON message:', e);
            }
            return;
        }

        const data = new Uint8Array(event.data);
        if (data.length < 1) return;

        const msgType = data[0];

        switch (msgType) {
            case MSG_FRAME:
                this.handleFrame(data);
                break;
            case MSG_AUDIO:
                this.handleAudio(data);
                break;
            case MSG_CONFIG:
                this.handleConfig(data);
                break;
            case MSG_STATUS:
                this.handleStatus(data);
                break;
            default:
                console.warn('Unknown message type:', msgType);
        }
    }

    handleJsonMessage(data) {
        if (data.type === 'connected') {
            console.log('Assigned client ID:', data.id);
        } else if (data.type === 'pong') {
            this.latency = performance.now() - this.lastPingTime;
            document.getElementById('latency-display').textContent =
                `Latency: ${Math.round(this.latency)} ms`;
        }
    }

    handleFrame(data) {
        if (data.length < 9) return;

        const view = new DataView(data.buffer);
        const width = view.getUint32(1, true);
        const height = view.getUint32(5, true);

        // Validate dimensions
        if (width === 0 || height === 0 || width > 4096 || height > 4096) {
            console.error(`Invalid frame dimensions: ${width}x${height}`);
            return;
        }

        // Validate data length
        const expectedLength = 9 + width * height * 4;
        if (data.length < expectedLength) {
            console.error(`Frame data too short: ${data.length} < ${expectedLength}`);
            return;
        }

        // Check if frame dimensions changed
        if (this.frameWidth !== width || this.frameHeight !== height) {
            this.frameWidth = width;
            this.frameHeight = height;

            const dpr = window.devicePixelRatio || 1;
            console.log(`Frame: ${width}x${height}, DPR: ${dpr}`);

            // Canvas buffer = frame dimensions exactly
            this.canvas.width = width;
            this.canvas.height = height;

            // CSS size: use exact pixel dimensions divided by DPR
            // This makes 1 Mac pixel = 1 device pixel (true pixel-perfect)
            const cssWidth = width / dpr;
            const cssHeight = height / dpr;
            this.canvas.style.width = cssWidth + 'px';
            this.canvas.style.height = cssHeight + 'px';

            console.log(`CSS size: ${cssWidth}x${cssHeight}px (DPR: ${dpr})`);

            document.getElementById('resolution').textContent =
                `${width} x ${height} (${this.useWebGL ? 'WebGL' : '2D'}, DPR: ${dpr})`;
        }

        // Extract pixel data
        const pixelData = new Uint8Array(
            data.buffer, data.byteOffset + 9, width * height * 4
        );

        if (this.useWebGL) {
            // WebGL path - upload texture and render
            this.renderer.updateTexture(pixelData, width, height);
            this.renderer.render();
        } else {
            // Canvas 2D fallback
            const imageData = new ImageData(
                new Uint8ClampedArray(pixelData.buffer, pixelData.byteOffset, pixelData.length),
                width, height
            );
            this.ctx.putImageData(imageData, 0, 0);
        }

        this.frameCount++;
        this.bytesReceived += data.length;
    }

    handleAudio(data) {
        if (!this.audioContext || data.length < 9) return;

        const view = new DataView(data.buffer);
        const sampleRate = view.getUint32(1, true);
        const sampleCount = view.getUint32(5, true);

        // Convert int16 to float32
        const samples = new Float32Array(sampleCount);
        for (let i = 0; i < sampleCount; i++) {
            samples[i] = view.getInt16(9 + i * 2, true) / 32768;
        }

        // Create audio buffer
        const buffer = this.audioContext.createBuffer(1, sampleCount, sampleRate);
        buffer.getChannelData(0).set(samples);

        // Schedule playback
        const source = this.audioContext.createBufferSource();
        source.buffer = buffer;
        source.connect(this.audioContext.destination);

        const now = this.audioContext.currentTime;
        if (this.nextAudioTime < now) {
            this.nextAudioTime = now;
        }
        source.start(this.nextAudioTime);
        this.nextAudioTime += buffer.duration;
    }

    handleConfig(data) {
        // Config response (JSON string after type byte)
        const json = new TextDecoder().decode(data.slice(1));
        console.log('Config response:', json);

        // Dispatch event for config UI
        window.dispatchEvent(new CustomEvent('configResponse', {
            detail: JSON.parse(json)
        }));
    }

    handleStatus(data) {
        // Status message
        const json = new TextDecoder().decode(data.slice(1));
        console.log('Status:', json);
    }

    initAudio() {
        if (this.audioContext) return;

        try {
            this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            console.log('Audio context initialized');
        } catch (e) {
            console.warn('Could not create audio context:', e);
        }
    }

    setupInputHandlers() {
        // Mouse events
        this.canvas.addEventListener('mousedown', (e) => {
            this.initAudio(); // Init on first interaction
            this.sendMouseEvent(INPUT_MOUSE_DOWN, e);
        });

        this.canvas.addEventListener('mouseup', (e) => {
            this.sendMouseEvent(INPUT_MOUSE_UP, e);
        });

        this.canvas.addEventListener('mousemove', (e) => {
            if (this.connected) {
                this.sendMouseEvent(INPUT_MOUSE_MOVE, e);
            }
        });

        // Prevent context menu
        this.canvas.addEventListener('contextmenu', (e) => {
            e.preventDefault();
        });

        // Keyboard events
        document.addEventListener('keydown', (e) => {
            if (this.connected && !e.repeat) {
                this.sendKeyEvent(INPUT_KEY_DOWN, e);
                e.preventDefault();
            }
        });

        document.addEventListener('keyup', (e) => {
            if (this.connected) {
                this.sendKeyEvent(INPUT_KEY_UP, e);
                e.preventDefault();
            }
        });

        // Click overlay to reconnect
        document.getElementById('overlay').addEventListener('click', () => {
            if (!this.connected) {
                this.connect();
            }
        });
    }

    sendMouseEvent(type, event) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

        const rect = this.canvas.getBoundingClientRect();
        const scaleX = this.canvas.width / rect.width;
        const scaleY = this.canvas.height / rect.height;

        const x = Math.round((event.clientX - rect.left) * scaleX);
        const y = Math.round((event.clientY - rect.top) * scaleY);

        // Build binary message
        const buffer = new ArrayBuffer(type === INPUT_MOUSE_MOVE ? 6 : 7);
        const view = new DataView(buffer);

        view.setUint8(0, MSG_INPUT);
        view.setUint8(1, type);
        view.setInt16(2, x, true);
        view.setInt16(4, y, true);

        if (type !== INPUT_MOUSE_MOVE) {
            view.setUint8(6, event.button);
        }

        this.ws.send(buffer);
    }

    sendKeyEvent(type, event) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

        // Map browser keyCode to Mac keycode
        const keycode = this.mapKeyCode(event.code);
        if (keycode === -1) return;

        // Build binary message
        const buffer = new ArrayBuffer(5);
        const view = new DataView(buffer);

        view.setUint8(0, MSG_INPUT);
        view.setUint8(1, type);
        view.setUint16(2, keycode, true);

        // Modifiers
        let modifiers = 0;
        if (event.ctrlKey) modifiers |= 0x01;
        if (event.altKey) modifiers |= 0x02;
        if (event.shiftKey) modifiers |= 0x04;
        if (event.metaKey) modifiers |= 0x08;
        view.setUint8(4, modifiers);

        this.ws.send(buffer);
    }

    mapKeyCode(code) {
        // Browser code -> Mac keycode mapping
        const keyMap = {
            'KeyA': 0x00, 'KeyS': 0x01, 'KeyD': 0x02, 'KeyF': 0x03,
            'KeyH': 0x04, 'KeyG': 0x05, 'KeyZ': 0x06, 'KeyX': 0x07,
            'KeyC': 0x08, 'KeyV': 0x09, 'KeyB': 0x0B, 'KeyQ': 0x0C,
            'KeyW': 0x0D, 'KeyE': 0x0E, 'KeyR': 0x0F, 'KeyY': 0x10,
            'KeyT': 0x11, 'Digit1': 0x12, 'Digit2': 0x13, 'Digit3': 0x14,
            'Digit4': 0x15, 'Digit6': 0x16, 'Digit5': 0x17, 'Equal': 0x18,
            'Digit9': 0x19, 'Digit7': 0x1A, 'Minus': 0x1B, 'Digit8': 0x1C,
            'Digit0': 0x1D, 'BracketRight': 0x1E, 'KeyO': 0x1F, 'KeyU': 0x20,
            'BracketLeft': 0x21, 'KeyI': 0x22, 'KeyP': 0x23, 'Enter': 0x24,
            'KeyL': 0x25, 'KeyJ': 0x26, 'Quote': 0x27, 'KeyK': 0x28,
            'Semicolon': 0x29, 'Backslash': 0x2A, 'Comma': 0x2B,
            'Slash': 0x2C, 'KeyN': 0x2D, 'KeyM': 0x2E, 'Period': 0x2F,
            'Tab': 0x30, 'Space': 0x31, 'Backquote': 0x32, 'Backspace': 0x33,
            'Escape': 0x35, 'MetaLeft': 0x37, 'ShiftLeft': 0x38,
            'CapsLock': 0x39, 'AltLeft': 0x3A, 'ControlLeft': 0x3B,
            'ShiftRight': 0x3C, 'AltRight': 0x3D, 'ControlRight': 0x3E,
            'ArrowLeft': 0x7B, 'ArrowRight': 0x7C, 'ArrowDown': 0x7D,
            'ArrowUp': 0x7E, 'F1': 0x7A, 'F2': 0x78, 'F3': 0x63,
            'F4': 0x76, 'F5': 0x60, 'F6': 0x61, 'F7': 0x62, 'F8': 0x64,
            'F9': 0x65, 'F10': 0x6D, 'F11': 0x67, 'F12': 0x6F,
            'Delete': 0x75, 'Home': 0x73, 'End': 0x77, 'PageUp': 0x74,
            'PageDown': 0x79
        };

        return keyMap[code] !== undefined ? keyMap[code] : -1;
    }

    sendPing() {
        if (!this.connected || !this.ws) return;

        this.lastPingTime = performance.now();

        // Send status message with timestamp
        const buffer = new ArrayBuffer(5);
        const view = new DataView(buffer);
        view.setUint8(0, MSG_STATUS);
        view.setUint32(1, Math.round(this.latency), true);
        this.ws.send(buffer);
    }

    updateFps() {
        const now = performance.now();
        const elapsed = now - this.lastFpsTime;
        this.fps = Math.round((this.frameCount / elapsed) * 1000);
        this.frameCount = 0;
        this.lastFpsTime = now;

        // Calculate bandwidth
        const bwElapsed = (now - this.lastBandwidthTime) / 1000;
        if (bwElapsed > 0) {
            this.bandwidth = this.bytesReceived / bwElapsed;
            this.bytesReceived = 0;
            this.lastBandwidthTime = now;
        }

        // Format bandwidth for display
        let bwText;
        if (this.bandwidth >= 1024 * 1024) {
            bwText = `${(this.bandwidth / (1024 * 1024)).toFixed(1)} MB/s`;
        } else if (this.bandwidth >= 1024) {
            bwText = `${(this.bandwidth / 1024).toFixed(0)} KB/s`;
        } else {
            bwText = `${Math.round(this.bandwidth)} B/s`;
        }

        document.getElementById('fps-display').textContent =
            `FPS: ${this.fps} | ${bwText}`;
    }

    updateStatus(connected) {
        const dot = document.getElementById('status-dot');
        const text = document.getElementById('connection-status');
        const btn = document.getElementById('connect-btn');

        if (connected) {
            dot.classList.add('connected');
            dot.classList.remove('disconnected');
            text.textContent = 'Connected';
            btn.textContent = 'Disconnect';
        } else {
            dot.classList.remove('connected');
            dot.classList.add('disconnected');
            text.textContent = 'Disconnected';
            btn.textContent = 'Connect';
        }
    }

    updateOverlay(text, showSpinner) {
        const overlay = document.getElementById('overlay');
        const overlayText = document.getElementById('overlay-text');
        const spinner = overlay.querySelector('.spinner');

        overlay.classList.remove('hidden');
        overlayText.textContent = text;
        spinner.style.display = showSpinner ? 'block' : 'none';
    }

    hideOverlay() {
        document.getElementById('overlay').classList.add('hidden');
    }

    // Config methods
    sendConfigCommand(cmd, data = {}) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

        const json = JSON.stringify({ cmd, ...data });
        const buffer = new ArrayBuffer(1 + json.length);
        const view = new Uint8Array(buffer);
        view[0] = MSG_CONFIG;
        new TextEncoder().encodeInto(json, view.subarray(1));
        this.ws.send(buffer);
    }

    getConfig() {
        this.sendConfigCommand('get_config');
    }

    setConfig(config) {
        this.sendConfigCommand('set_config', { config });
    }

    restart() {
        this.sendConfigCommand('restart');
    }
}

// Global client instance
const client = new BasiliskClient();

// Global functions for HTML buttons
function toggleConnection() {
    if (client.connected) {
        client.disconnect();
    } else {
        client.connect();
    }
}

function toggleFullscreen() {
    if (document.fullscreenElement) {
        document.exitFullscreen();
        document.body.classList.remove('fullscreen');
    } else {
        document.documentElement.requestFullscreen();
        document.body.classList.add('fullscreen');
    }
}

// Handle fullscreen change
document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
        document.body.classList.remove('fullscreen');
    }
});

// Auto-connect if URL has ?autoconnect
if (window.location.search.includes('autoconnect')) {
    window.addEventListener('load', () => client.connect());
}
