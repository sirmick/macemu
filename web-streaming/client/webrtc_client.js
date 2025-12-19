/**
 * Basilisk II WebRTC Client
 *
 * Connects to GStreamer webrtcsink signaling server, establishes WebRTC
 * peer connection, and displays video stream with input handling.
 */

class BasiliskWebRTCClient {
    constructor(options = {}) {
        this.video = document.getElementById('display');
        this.signalingPort = options.port || 8090;
        this.signalingUrl = options.url || `ws://${location.hostname}:${this.signalingPort}`;

        this.ws = null;
        this.pc = null;
        this.dataChannel = null;
        this.peerId = null;
        this.sessionId = null;
        this.producerId = null;
        this.connected = false;

        // Stats tracking
        this.stats = {
            fps: 0,
            latency: 0,
            bytesReceived: 0,
            framesDecoded: 0
        };
        this.lastStatsTime = performance.now();
        this.lastBytesReceived = 0;
        this.lastFramesDecoded = 0;

        // Auto-reconnect
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 2000;

        // Parse URL parameters
        const params = new URLSearchParams(window.location.search);
        if (params.get('server')) {
            this.signalingUrl = params.get('server');
        }
        if (params.get('port')) {
            this.signalingPort = parseInt(params.get('port'));
            this.signalingUrl = `ws://${location.hostname}:${this.signalingPort}`;
        }
    }

    async connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            console.log('Already connected');
            return;
        }

        this.updateStatus('Connecting...');
        console.log('Connecting to:', this.signalingUrl);

        try {
            this.ws = new WebSocket(this.signalingUrl);

            this.ws.onopen = () => this.onSignalingOpen();
            this.ws.onmessage = (e) => this.onSignalingMessage(e);
            this.ws.onclose = (e) => this.onSignalingClose(e);
            this.ws.onerror = (e) => this.onSignalingError(e);
        } catch (e) {
            console.error('WebSocket connection failed:', e);
            this.updateStatus('Connection failed');
            this.scheduleReconnect();
        }
    }

    disconnect() {
        this.reconnectAttempts = this.maxReconnectAttempts; // Prevent auto-reconnect

        if (this.dataChannel) {
            this.dataChannel.close();
            this.dataChannel = null;
        }

        if (this.pc) {
            this.pc.close();
            this.pc = null;
        }

        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }

        this.connected = false;
        this.peerId = null;
        this.sessionId = null;
        this.producerId = null;

        this.updateStatus('Disconnected');
        this.updateConnectionUI(false);

        if (this.video) {
            this.video.srcObject = null;
        }
    }

    onSignalingOpen() {
        console.log('DEBUG: onSignalingOpen called');
        console.log('Signaling WebSocket connected');
        this.reconnectAttempts = 0;
        this.updateStatus('Connected to signaling server');
        // Server will send 'welcome' message with our peer ID
    }

    onSignalingMessage(event) {
        console.log('DEBUG: onSignalingMessage called, raw data:', event.data);
        let msg;
        try {
            msg = JSON.parse(event.data);
        } catch (e) {
            console.error('Failed to parse signaling message:', e);
            return;
        }

        console.log('DEBUG: parsed message type:', msg.type);
        console.log('Signaling message:', msg.type || msg);

        switch (msg.type) {
            case 'welcome':
                console.log('DEBUG: about to call handleWelcome');
                this.handleWelcome(msg);
                console.log('DEBUG: handleWelcome returned');
                break;

            case 'peerStatusChanged':
                this.handlePeerStatusChanged(msg);
                break;

            case 'sessionStarted':
                this.handleSessionStarted(msg);
                break;

            case 'peer':
                this.handlePeerMessage(msg);
                break;

            case 'endSession':
                this.handleEndSession(msg);
                break;

            case 'error':
                console.error('Signaling error:', msg.details);
                this.updateStatus('Error: ' + msg.details);
                break;

            case 'list':
                this.handleProducerList(msg);
                break;

            default:
                console.log('Unknown signaling message type:', msg.type);
        }
    }

    handleWelcome(msg) {
        this.peerId = msg.peerId;
        console.log('Assigned peer ID:', this.peerId);

        // Register as a listener (consumer)
        const payload = JSON.stringify({
            type: 'setPeerStatus',
            roles: ['listener'],
            meta: { name: 'Basilisk II Web Client' }
        });
        console.log('DEBUG: payload type:', typeof payload);
        console.log('DEBUG: payload value:', payload);
        console.log('DEBUG: payload length:', payload.length);
        console.log('DEBUG: ws.binaryType:', this.ws.binaryType);
        this.ws.send(payload);
        console.log('DEBUG: message sent');
    }

    handlePeerStatusChanged(msg) {
        console.log('Peer status changed:', msg);

        // If this is our own status change confirming we're a listener, request producer list
        if (msg.peerId === this.peerId && msg.roles && msg.roles.includes('listener')) {
            console.log('DEBUG: Registered as listener, requesting producer list');
            this.ws.send(JSON.stringify({ type: 'list' }));
            return;
        }

        // Look for producers
        if (msg.roles && msg.roles.includes('producer')) {
            this.producerId = msg.peerId;
            console.log('Found producer:', this.producerId);

            // Start session with producer
            this.ws.send(JSON.stringify({
                type: 'startSession',
                peerId: this.producerId
            }));
        }
    }

    handleProducerList(msg) {
        console.log('Producer list:', msg.producers);

        if (msg.producers && msg.producers.length > 0) {
            // Connect to first producer
            this.producerId = msg.producers[0].id;
            console.log('Connecting to producer:', this.producerId);

            this.ws.send(JSON.stringify({
                type: 'startSession',
                peerId: this.producerId
            }));
        } else {
            console.log('No producers available, waiting...');
            this.updateStatus('Waiting for producer...');
        }
    }

    handleSessionStarted(msg) {
        this.sessionId = msg.sessionId;
        console.log('Session started:', this.sessionId);
        this.createPeerConnection();
    }

    handlePeerMessage(msg) {
        if (msg.sdp) {
            this.handleSdpMessage(msg);
        } else if (msg.ice) {
            this.handleIceMessage(msg);
        }
    }

    async handleSdpMessage(msg) {
        console.log('Received SDP:', msg.sdp.type);

        if (!this.pc) {
            console.error('No peer connection');
            return;
        }

        try {
            await this.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));

            if (msg.sdp.type === 'offer') {
                const answer = await this.pc.createAnswer();
                await this.pc.setLocalDescription(answer);

                this.ws.send(JSON.stringify({
                    type: 'peer',
                    sessionId: this.sessionId,
                    sdp: this.pc.localDescription
                }));

                console.log('Sent SDP answer');
            }
        } catch (e) {
            console.error('SDP handling error:', e);
        }
    }

    async handleIceMessage(msg) {
        if (!this.pc) {
            console.error('No peer connection for ICE');
            return;
        }

        try {
            await this.pc.addIceCandidate(new RTCIceCandidate(msg.ice));
            console.log('Added ICE candidate');
        } catch (e) {
            console.warn('Failed to add ICE candidate:', e);
        }
    }

    handleEndSession(msg) {
        console.log('Session ended:', msg.sessionId);
        if (this.pc) {
            this.pc.close();
            this.pc = null;
        }
        this.connected = false;
        this.updateStatus('Session ended');
        this.updateConnectionUI(false);
    }

    createPeerConnection() {
        console.log('Creating peer connection');

        const config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };

        this.pc = new RTCPeerConnection(config);

        // Create DataChannel for sending input to server
        this.dataChannel = this.pc.createDataChannel('input', {
            ordered: true,
            maxRetransmits: 0  // Unreliable for low latency
        });
        this.setupDataChannel();

        this.pc.ontrack = (e) => {
            console.log('Received track:', e.track.kind);
            if (e.streams && e.streams[0]) {
                this.video.srcObject = e.streams[0];
                this.video.play().catch(e => console.warn('Video play failed:', e));
                this.connected = true;
                this.updateStatus('Connected');
                this.updateConnectionUI(true);
            }
        };

        this.pc.ondatachannel = (e) => {
            console.log('Received data channel from server:', e.channel.label);
            // Server might create additional channels for other purposes
        };

        this.pc.onicecandidate = (e) => {
            if (e.candidate) {
                this.ws.send(JSON.stringify({
                    type: 'peer',
                    sessionId: this.sessionId,
                    ice: e.candidate
                }));
            }
        };

        this.pc.oniceconnectionstatechange = () => {
            console.log('ICE connection state:', this.pc.iceConnectionState);
            if (this.pc.iceConnectionState === 'failed') {
                this.updateStatus('Connection failed');
                this.connected = false;
                this.updateConnectionUI(false);
            } else if (this.pc.iceConnectionState === 'disconnected') {
                this.updateStatus('Disconnected');
                this.connected = false;
                this.updateConnectionUI(false);
            }
        };

        this.pc.onconnectionstatechange = () => {
            console.log('Connection state:', this.pc.connectionState);
        };
    }

    setupDataChannel() {
        if (!this.dataChannel) return;

        this.dataChannel.onopen = () => {
            console.log('Data channel opened');
            this.setupInputHandlers();
        };

        this.dataChannel.onclose = () => {
            console.log('Data channel closed');
        };

        this.dataChannel.onerror = (e) => {
            console.error('Data channel error:', e);
        };

        this.dataChannel.onmessage = (e) => {
            console.log('Data channel message:', e.data);
        };
    }

    setupInputHandlers() {
        if (!this.video) return;

        // Remove any existing handlers
        this.video.onmousemove = null;
        this.video.onmousedown = null;
        this.video.onmouseup = null;
        this.video.oncontextmenu = null;

        // Mouse move
        this.video.addEventListener('mousemove', (e) => {
            if (!this.connected) return;
            const coords = this.getVideoCoords(e);
            this.sendInput({ type: 'mouse_move', x: coords.x, y: coords.y });
        });

        // Mouse buttons
        this.video.addEventListener('mousedown', (e) => {
            e.preventDefault();
            if (!this.connected) return;
            const coords = this.getVideoCoords(e);
            this.sendInput({ type: 'mouse_down', x: coords.x, y: coords.y, button: e.button });
        });

        this.video.addEventListener('mouseup', (e) => {
            if (!this.connected) return;
            const coords = this.getVideoCoords(e);
            this.sendInput({ type: 'mouse_up', x: coords.x, y: coords.y, button: e.button });
        });

        // Prevent context menu
        this.video.addEventListener('contextmenu', (e) => e.preventDefault());

        // Keyboard events (on document to capture all keys)
        document.addEventListener('keydown', (e) => {
            if (!this.connected) return;
            // Don't capture if typing in an input field
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

            e.preventDefault();
            this.sendInput({
                type: 'key_down',
                keyCode: e.keyCode,
                code: e.code,
                key: e.key,
                ctrl: e.ctrlKey,
                alt: e.altKey,
                shift: e.shiftKey,
                meta: e.metaKey
            });
        });

        document.addEventListener('keyup', (e) => {
            if (!this.connected) return;
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

            e.preventDefault();
            this.sendInput({
                type: 'key_up',
                keyCode: e.keyCode,
                code: e.code,
                key: e.key,
                ctrl: e.ctrlKey,
                alt: e.altKey,
                shift: e.shiftKey,
                meta: e.metaKey
            });
        });

        console.log('Input handlers set up');
    }

    getVideoCoords(event) {
        const rect = this.video.getBoundingClientRect();
        const videoWidth = this.video.videoWidth || 640;
        const videoHeight = this.video.videoHeight || 480;

        const scaleX = videoWidth / rect.width;
        const scaleY = videoHeight / rect.height;

        return {
            x: Math.round((event.clientX - rect.left) * scaleX),
            y: Math.round((event.clientY - rect.top) * scaleY)
        };
    }

    sendInput(msg) {
        if (this.dataChannel && this.dataChannel.readyState === 'open') {
            this.dataChannel.send(JSON.stringify(msg));
        }
    }

    onSignalingClose(event) {
        console.log('Signaling WebSocket closed:', event.code, event.reason);
        this.connected = false;
        this.updateStatus('Disconnected');
        this.updateConnectionUI(false);

        this.scheduleReconnect();
    }

    onSignalingError(event) {
        console.error('Signaling WebSocket error:', event);
        this.updateStatus('Connection error');
    }

    scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.log('Max reconnect attempts reached');
            this.updateStatus('Connection failed - click to retry');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * this.reconnectAttempts;
        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
        this.updateStatus(`Reconnecting in ${delay / 1000}s...`);

        setTimeout(() => {
            if (!this.connected) {
                this.connect();
            }
        }, delay);
    }

    updateStatus(text) {
        const el = document.getElementById('status');
        if (el) el.textContent = text;
        console.log('Status:', text);
    }

    updateConnectionUI(connected) {
        const dot = document.getElementById('status-dot');
        const text = document.getElementById('connection-status');
        const btn = document.getElementById('connect-btn');

        if (dot) {
            dot.classList.toggle('connected', connected);
            dot.classList.toggle('disconnected', !connected);
        }

        if (text) {
            text.textContent = connected ? 'Connected' : 'Disconnected';
        }

        if (btn) {
            btn.textContent = connected ? 'Disconnect' : 'Connect';
        }
    }

    // Stats collection
    async updateStats() {
        if (!this.pc || !this.connected) return;

        try {
            const stats = await this.pc.getStats();
            const now = performance.now();
            const elapsed = (now - this.lastStatsTime) / 1000;

            stats.forEach(report => {
                if (report.type === 'inbound-rtp' && report.kind === 'video') {
                    const bytesReceived = report.bytesReceived || 0;
                    const framesDecoded = report.framesDecoded || 0;

                    if (elapsed > 0) {
                        this.stats.fps = Math.round((framesDecoded - this.lastFramesDecoded) / elapsed);
                        const bps = (bytesReceived - this.lastBytesReceived) * 8 / elapsed;
                        this.stats.bitrate = Math.round(bps / 1000); // kbps
                    }

                    this.lastBytesReceived = bytesReceived;
                    this.lastFramesDecoded = framesDecoded;
                }
            });

            this.lastStatsTime = now;

            // Update display
            const fpsEl = document.getElementById('fps-display');
            if (fpsEl) {
                fpsEl.textContent = `FPS: ${this.stats.fps} | ${this.stats.bitrate || 0} kbps`;
            }

            const resEl = document.getElementById('resolution');
            if (resEl && this.video.videoWidth) {
                resEl.textContent = `${this.video.videoWidth} x ${this.video.videoHeight}`;
            }
        } catch (e) {
            console.warn('Stats error:', e);
        }
    }

    startStatsInterval() {
        setInterval(() => this.updateStats(), 1000);
    }
}

// Global client instance
let client = null;

function initClient() {
    client = new BasiliskWebRTCClient();
    client.startStatsInterval();

    // Auto-connect if URL parameter present
    if (window.location.search.includes('autoconnect')) {
        client.connect();
    }
}

function toggleConnection() {
    if (!client) {
        initClient();
    }

    if (client.connected) {
        client.disconnect();
    } else {
        client.reconnectAttempts = 0;
        client.connect();
    }
}

function toggleFullscreen() {
    const container = document.getElementById('display-container') || document.body;

    if (document.fullscreenElement) {
        document.exitFullscreen();
    } else {
        container.requestFullscreen().catch(e => console.warn('Fullscreen failed:', e));
    }
}

// Initialize on page load
window.addEventListener('load', initClient);
