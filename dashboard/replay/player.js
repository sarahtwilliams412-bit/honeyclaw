/**
 * Honeyclaw Session Replay Player
 * JavaScript controller for the replay dashboard
 */

class HoneyclawPlayer {
    constructor() {
        this.player = null;
        this.recording = null;
        this.info = null;
        this.events = [];
        this.currentEventIndex = 0;
        this.isPlaying = false;
        
        this.init();
    }
    
    async init() {
        await this.loadRecording();
        this.setupPlayer();
        this.setupControls();
        this.setupTimeline();
        this.populateEventList();
        this.updateInfo();
    }
    
    async loadRecording() {
        try {
            // Load recording data
            const recordingResp = await fetch('/api/recording');
            this.recording = await recordingResp.json();
            
            // Load info
            const infoResp = await fetch('/api/info');
            this.info = await infoResp.json();
            
            // Extract events
            this.events = this.recording.events || [];
            
        } catch (error) {
            console.error('Failed to load recording:', error);
            document.getElementById('player').innerHTML = 
                '<div class="loading" style="color: #f44336;">❌ Failed to load recording</div>';
        }
    }
    
    setupPlayer() {
        const playerEl = document.getElementById('player');
        
        if (this.recording.protocol === 'ssh') {
            // Use asciinema player for SSH recordings
            this.player = AsciinemaPlayer.create(
                '/api/cast',
                playerEl,
                {
                    cols: this.recording.metadata?.width || 80,
                    rows: this.recording.metadata?.height || 24,
                    autoPlay: false,
                    loop: false,
                    speed: 1,
                    idleTimeLimit: 2,
                    theme: 'monokai',
                    fit: 'width',
                    controls: false,  // We'll use our own controls
                }
            );
            
            // Listen to player events
            this.player.addEventListener('play', () => {
                this.isPlaying = true;
                this.updatePlayButton();
            });
            
            this.player.addEventListener('pause', () => {
                this.isPlaying = false;
                this.updatePlayButton();
            });
            
            // Update timeline on time change
            setInterval(() => this.updateTimeline(), 100);
            
        } else {
            // For HTTP recordings, show a custom view
            playerEl.innerHTML = '<div class="http-replay">HTTP replay not yet implemented</div>';
        }
    }
    
    setupControls() {
        // Play button
        document.getElementById('btn-play').addEventListener('click', () => {
            if (this.player) {
                this.player.play();
            }
        });
        
        // Pause button
        document.getElementById('btn-pause').addEventListener('click', () => {
            if (this.player) {
                this.player.pause();
            }
        });
        
        // Restart button
        document.getElementById('btn-restart').addEventListener('click', () => {
            if (this.player) {
                this.player.seek(0);
                this.player.play();
            }
        });
        
        // Speed control
        document.getElementById('speed-select').addEventListener('change', (e) => {
            if (this.player) {
                this.player.setSpeed(parseFloat(e.target.value));
            }
        });
        
        // Export buttons
        document.getElementById('btn-download-cast').addEventListener('click', () => {
            this.downloadCast();
        });
        
        document.getElementById('btn-download-txt').addEventListener('click', () => {
            this.downloadText();
        });
        
        document.getElementById('btn-copy-link').addEventListener('click', () => {
            this.copyShareLink();
        });
    }
    
    setupTimeline() {
        const timeline = document.getElementById('timeline');
        const markers = document.getElementById('timeline-markers');
        
        // Click on timeline to seek
        timeline.addEventListener('click', (e) => {
            const rect = timeline.getBoundingClientRect();
            const percent = (e.clientX - rect.left) / rect.width;
            const duration = this.recording.state?.duration_ms || 0;
            const seekTime = (percent * duration) / 1000;
            
            if (this.player) {
                this.player.seek(seekTime);
            }
        });
        
        // Add event markers
        const duration = this.recording.state?.duration_ms || 1;
        this.events.forEach((event, index) => {
            const percent = (event.timestamp_ms / duration) * 100;
            const marker = document.createElement('div');
            marker.className = `timeline-marker ${event.event_type}`;
            marker.style.left = `${percent}%`;
            marker.title = `${this.formatTime(event.timestamp_ms)} - ${event.event_type}`;
            marker.addEventListener('click', () => {
                if (this.player) {
                    this.player.seek(event.timestamp_ms / 1000);
                }
            });
            markers.appendChild(marker);
        });
    }
    
    updateTimeline() {
        if (!this.player) return;
        
        const currentTime = this.player.getCurrentTime() || 0;
        const duration = this.player.getDuration() || 1;
        const percent = (currentTime / duration) * 100;
        
        document.getElementById('timeline-progress').style.width = `${percent}%`;
        
        // Update time display
        const durationMs = this.recording.state?.duration_ms || 0;
        const currentMs = currentTime * 1000;
        document.getElementById('time-display').textContent = 
            `${this.formatTime(currentMs)} / ${this.formatTime(durationMs)}`;
        
        // Update active event in list
        this.updateActiveEvent(currentMs);
    }
    
    updateActiveEvent(currentMs) {
        const items = document.querySelectorAll('.event-item');
        items.forEach((item, index) => {
            const eventTime = this.events[index]?.timestamp_ms || 0;
            const isActive = eventTime <= currentMs && 
                (index === this.events.length - 1 || this.events[index + 1].timestamp_ms > currentMs);
            item.classList.toggle('active', isActive);
        });
    }
    
    updatePlayButton() {
        const playBtn = document.getElementById('btn-play');
        const pauseBtn = document.getElementById('btn-pause');
        
        if (this.isPlaying) {
            playBtn.style.display = 'none';
            pauseBtn.style.display = 'inline-flex';
        } else {
            playBtn.style.display = 'inline-flex';
            pauseBtn.style.display = 'none';
        }
    }
    
    populateEventList() {
        const eventList = document.getElementById('event-list');
        eventList.innerHTML = '';
        
        // Show max 100 events for performance
        const eventsToShow = this.events.slice(0, 100);
        
        eventsToShow.forEach((event, index) => {
            const item = document.createElement('div');
            item.className = 'event-item';
            
            // Format data (escape HTML, truncate long strings)
            let displayData = event.data;
            if (typeof displayData === 'string') {
                displayData = this.escapeHtml(displayData);
                if (displayData.length > 100) {
                    displayData = displayData.substring(0, 100) + '...';
                }
                // Replace control characters with visible representations
                displayData = displayData
                    .replace(/\r/g, '⏎')
                    .replace(/\n/g, '↵\n')
                    .replace(/\t/g, '→');
            } else {
                displayData = JSON.stringify(displayData).substring(0, 100);
            }
            
            item.innerHTML = `
                <span class="event-time">${this.formatTime(event.timestamp_ms)}</span>
                <span class="event-type ${event.event_type}">${event.event_type}</span>
                <span class="event-data">${displayData}</span>
            `;
            
            item.addEventListener('click', () => {
                if (this.player) {
                    this.player.seek(event.timestamp_ms / 1000);
                }
            });
            
            eventList.appendChild(item);
        });
        
        if (this.events.length > 100) {
            const more = document.createElement('div');
            more.className = 'event-item';
            more.innerHTML = `<span style="color: var(--text-secondary);">... and ${this.events.length - 100} more events</span>`;
            eventList.appendChild(more);
        }
    }
    
    updateInfo() {
        if (!this.info) return;
        
        document.getElementById('info-session-id').textContent = this.info.session_id || '-';
        document.getElementById('info-protocol').textContent = (this.info.protocol || '-').toUpperCase();
        document.getElementById('info-source-ip').textContent = this.info.source_ip || '-';
        document.getElementById('info-username').textContent = this.info.username || '-';
        document.getElementById('info-start-time').textContent = this.formatDateTime(this.info.start_time);
        document.getElementById('info-duration').textContent = this.info.duration_human || '-';
        document.getElementById('info-events').textContent = this.info.event_count || this.events.length;
    }
    
    formatTime(ms) {
        const totalSeconds = Math.floor(ms / 1000);
        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;
        return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
    
    formatDateTime(isoString) {
        if (!isoString) return '-';
        try {
            const date = new Date(isoString);
            return date.toLocaleString();
        } catch {
            return isoString;
        }
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    async downloadCast() {
        try {
            const response = await fetch('/api/cast');
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `${this.info?.session_id || 'session'}.cast`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Download failed:', error);
            alert('Failed to download recording');
        }
    }
    
    downloadText() {
        // Concatenate all output events
        let text = `Honeyclaw Session Recording\n`;
        text += `Session: ${this.info?.session_id || 'unknown'}\n`;
        text += `Source: ${this.info?.source_ip || 'unknown'}\n`;
        text += `Time: ${this.info?.start_time || 'unknown'}\n`;
        text += `${'='.repeat(60)}\n\n`;
        
        this.events.forEach(event => {
            if (event.event_type === 'output' || event.event_type === 'input') {
                text += event.data;
            }
        });
        
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `${this.info?.session_id || 'session'}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    
    copyShareLink() {
        const shareToken = this.info?.share_token;
        let shareUrl;
        
        if (shareToken) {
            shareUrl = `${window.location.origin}/replay/shared/${shareToken}`;
        } else {
            shareUrl = window.location.href;
        }
        
        navigator.clipboard.writeText(shareUrl).then(() => {
            const btn = document.getElementById('btn-copy-link');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<span class="icon">✓</span> Copied!';
            setTimeout(() => {
                btn.innerHTML = originalText;
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy:', err);
            alert(`Share URL: ${shareUrl}`);
        });
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.honeyclawPlayer = new HoneyclawPlayer();
});
