/*
 * Simple WebRTC client for libdatachannel backend
 *
 * Uses a simpler signaling protocol than webrtcsink.
 */

class BasiliskWebRTC {
    constructor(videoElement, statusCallback) {
        this.video = videoElement;
        this.onStatus = statusCallback || (() => {});
        this.ws = null;
        this.pc = null;
        this.dataChannel = null;
        this.connected = false;
    }

    connect(wsUrl) {
        this.onStatus('Connecting...');

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            this.onStatus('Signaling connected');
            // Request connection
            this.ws.send(JSON.stringify({ type: 'connect' }));
        };

        this.ws.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            this.handleSignaling(msg);
        };

        this.ws.onclose = () => {
            this.onStatus('Disconnected');
            this.connected = false;
            this.cleanup();
            // Reconnect after delay
            setTimeout(() => this.connect(wsUrl), 3000);
        };

        this.ws.onerror = (e) => {
            console.error('WebSocket error:', e);
        };
    }

    async handleSignaling(msg) {
        console.log('Signaling:', msg.type);

        if (msg.type === 'welcome') {
            // Server acknowledged us
            this.onStatus('Waiting for offer...');

        } else if (msg.type === 'offer') {
            // Create peer connection and handle offer
            this.createPeerConnection();

            const offer = new RTCSessionDescription({
                type: 'offer',
                sdp: msg.sdp
            });

            await this.pc.setRemoteDescription(offer);
            const answer = await this.pc.createAnswer();
            await this.pc.setLocalDescription(answer);

            this.ws.send(JSON.stringify({
                type: 'answer',
                sdp: answer.sdp
            }));

        } else if (msg.type === 'candidate') {
            if (this.pc) {
                await this.pc.addIceCandidate(new RTCIceCandidate({
                    candidate: msg.candidate,
                    sdpMid: msg.mid
                }));
            }
        }
    }

    createPeerConnection() {
        this.pc = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });

        this.pc.ontrack = (e) => {
            console.log('Track received:', e.track.kind);
            if (e.streams && e.streams[0]) {
                this.video.srcObject = e.streams[0];
                this.video.play().catch(e => console.warn('Play failed:', e));
                this.connected = true;
                this.onStatus('Connected');
            }
        };

        this.pc.ondatachannel = (e) => {
            console.log('DataChannel received:', e.channel.label);
            this.dataChannel = e.channel;
            this.setupDataChannel();
        };

        this.pc.onicecandidate = (e) => {
            if (e.candidate) {
                this.ws.send(JSON.stringify({
                    type: 'candidate',
                    candidate: e.candidate.candidate,
                    mid: e.candidate.sdpMid
                }));
            }
        };

        this.pc.oniceconnectionstatechange = () => {
            console.log('ICE state:', this.pc.iceConnectionState);
            if (this.pc.iceConnectionState === 'failed') {
                this.onStatus('Connection failed');
            }
        };
    }

    setupDataChannel() {
        if (!this.dataChannel) return;

        this.dataChannel.onopen = () => {
            console.log('DataChannel open');
            this.setupInputHandlers();
        };

        this.dataChannel.onclose = () => {
            console.log('DataChannel closed');
        };
    }

    setupInputHandlers() {
        if (!this.video) return;

        // Get coordinates relative to video
        const getCoords = (e) => {
            const rect = this.video.getBoundingClientRect();
            const scaleX = this.video.videoWidth / rect.width;
            const scaleY = this.video.videoHeight / rect.height;
            return {
                x: Math.round((e.clientX - rect.left) * scaleX),
                y: Math.round((e.clientY - rect.top) * scaleY)
            };
        };

        this.video.addEventListener('mousemove', (e) => {
            const coords = getCoords(e);
            this.sendInput({ type: 'mouse_move', x: coords.x, y: coords.y });
        });

        this.video.addEventListener('mousedown', (e) => {
            e.preventDefault();
            const coords = getCoords(e);
            this.sendInput({ type: 'mouse_down', x: coords.x, y: coords.y, button: e.button });
        });

        this.video.addEventListener('mouseup', (e) => {
            e.preventDefault();
            const coords = getCoords(e);
            this.sendInput({ type: 'mouse_up', x: coords.x, y: coords.y, button: e.button });
        });

        this.video.addEventListener('contextmenu', (e) => e.preventDefault());

        document.addEventListener('keydown', (e) => {
            if (!this.connected) return;
            e.preventDefault();
            this.sendInput({
                type: 'key_down',
                keyCode: e.keyCode,
                ctrl: e.ctrlKey,
                alt: e.altKey,
                shift: e.shiftKey,
                meta: e.metaKey
            });
        });

        document.addEventListener('keyup', (e) => {
            if (!this.connected) return;
            e.preventDefault();
            this.sendInput({
                type: 'key_up',
                keyCode: e.keyCode,
                ctrl: e.ctrlKey,
                alt: e.altKey,
                shift: e.shiftKey,
                meta: e.metaKey
            });
        });
    }

    sendInput(msg) {
        if (this.dataChannel && this.dataChannel.readyState === 'open') {
            this.dataChannel.send(JSON.stringify(msg));
        }
    }

    cleanup() {
        if (this.dataChannel) {
            this.dataChannel.close();
            this.dataChannel = null;
        }
        if (this.pc) {
            this.pc.close();
            this.pc = null;
        }
    }

    disconnect() {
        this.cleanup();
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

// Auto-connect on page load
document.addEventListener('DOMContentLoaded', () => {
    const video = document.getElementById('screen');
    const status = document.getElementById('status');

    if (!video) {
        console.error('No video element found');
        return;
    }

    const client = new BasiliskWebRTC(video, (msg) => {
        console.log('Status:', msg);
        if (status) status.textContent = msg;
    });

    // Connect to same host on port 8090
    const wsUrl = `ws://${window.location.hostname}:8090`;
    client.connect(wsUrl);
});
