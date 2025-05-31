#!/usr/bin/env python3
"""
Manual Review Interface for Secret Scanner
Provides interface for manual review and triaging of discovered secrets
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_file
from loguru import logger
import threading
import webbrowser

class ManualReviewInterface:
    """Web-based interface for manual secret review"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Manual Review Interface
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.review_data_path = Path(config.get('data_storage_path', './data')) / 'review'
        self.review_data_path.mkdir(parents=True, exist_ok=True)
        
        # Flask app setup
        self.app = Flask(__name__)
        self.setup_routes()
        
        # Review session data
        self.current_session = {
            'findings': [],
            'reviewed': {},
            'session_id': None,
            'started_at': None
        }
        
        # Review statistics
        self.stats = {
            'total_reviewed': 0,
            'false_positives': 0,
            'true_positives': 0,
            'requires_action': 0,
            'review_times': []
        }
        
        logger.info("Manual Review Interface initialized")
    
    def setup_routes(self):
        """Setup Flask routes for the review interface"""
        
        @self.app.route('/')
        def index():
            """Main review interface"""
            return render_template_string(self.get_review_template())
        
        @self.app.route('/api/session', methods=['GET'])
        def get_session():
            """Get current review session data"""
            return jsonify({
                'session_id': self.current_session['session_id'],
                'total_findings': len(self.current_session['findings']),
                'reviewed': len(self.current_session['reviewed']),
                'remaining': len(self.current_session['findings']) - len(self.current_session['reviewed'])
            })
        
        @self.app.route('/api/finding/<int:index>', methods=['GET'])
        def get_finding(index):
            """Get a specific finding for review"""
            if 0 <= index < len(self.current_session['findings']):
                finding = self.current_session['findings'][index]
                # Ensure secret is redacted for display
                display_finding = finding.copy()
                if 'secret' in display_finding:
                    display_finding['secret_display'] = self._redact_secret(display_finding['secret'])
                return jsonify(display_finding)
            return jsonify({'error': 'Finding not found'}), 404
        
        @self.app.route('/api/finding/<int:index>/review', methods=['POST'])
        def review_finding(index):
            """Submit review for a finding"""
            if 0 <= index < len(self.current_session['findings']):
                review_data = request.json
                
                # Record review
                review = {
                    'reviewed_at': datetime.utcnow().isoformat(),
                    'verdict': review_data.get('verdict'),  # true_positive, false_positive, unsure
                    'severity_override': review_data.get('severity'),
                    'notes': review_data.get('notes', ''),
                    'requires_action': review_data.get('requires_action', False),
                    'action_taken': review_data.get('action_taken', ''),
                    'reviewer': review_data.get('reviewer', 'unknown')
                }
                
                self.current_session['reviewed'][index] = review
                
                # Update finding with review
                self.current_session['findings'][index]['manual_review'] = review
                
                # Update statistics
                self._update_review_stats(review)
                
                # Save progress
                self._save_review_progress()
                
                return jsonify({'success': True, 'review': review})
            
            return jsonify({'error': 'Finding not found'}), 404
        
        @self.app.route('/api/findings/batch', methods=['GET'])
        def get_findings_batch():
            """Get a batch of findings for review"""
            start = request.args.get('start', 0, type=int)
            limit = request.args.get('limit', 10, type=int)
            filter_type = request.args.get('filter', 'unreviewed')
            
            findings = []
            for i in range(start, min(start + limit, len(self.current_session['findings']))):
                if filter_type == 'all' or (filter_type == 'unreviewed' and i not in self.current_session['reviewed']):
                    finding = self.current_session['findings'][i].copy()
                    finding['index'] = i
                    finding['reviewed'] = i in self.current_session['reviewed']
                    if 'secret' in finding:
                        finding['secret_display'] = self._redact_secret(finding['secret'])
                    findings.append(finding)
            
            return jsonify({
                'findings': findings,
                'total': len(self.current_session['findings']),
                'start': start,
                'limit': limit
            })
        
        @self.app.route('/api/export', methods=['GET'])
        def export_reviews():
            """Export review results"""
            export_format = request.args.get('format', 'json')
            
            if export_format == 'json':
                export_file = self._export_reviews_json()
            elif export_format == 'csv':
                export_file = self._export_reviews_csv()
            else:
                return jsonify({'error': 'Unsupported format'}), 400
            
            if export_file and export_file.exists():
                return send_file(export_file, as_attachment=True)
            
            return jsonify({'error': 'Export failed'}), 500
        
        @self.app.route('/api/stats', methods=['GET'])
        def get_stats():
            """Get review statistics"""
            return jsonify(self.stats)
    
    def start_review_session(self, findings: List[Dict[str, Any]], 
                           auto_open: bool = True, 
                           port: int = 5000) -> None:
        """
        Start a manual review session
        
        Args:
            findings: List of findings to review
            auto_open: Whether to automatically open the browser
            port: Port to run the Flask server on
        """
        try:
            # Initialize session
            self.current_session = {
                'findings': findings,
                'reviewed': {},
                'session_id': datetime.utcnow().strftime('%Y%m%d_%H%M%S'),
                'started_at': datetime.utcnow().isoformat()
            }
            
            # Load any previous review progress
            self._load_review_progress()
            
            logger.info(f"Starting review session with {len(findings)} findings")
            
            # Start Flask in a separate thread
            server_thread = threading.Thread(
                target=lambda: self.app.run(host='127.0.0.1', port=port, debug=False),
                daemon=True
            )
            server_thread.start()
            
            # Open browser if requested
            if auto_open:
                time.sleep(1)  # Give server time to start
                webbrowser.open(f'http://127.0.0.1:{port}')
            
            logger.info(f"Manual review interface running at http://127.0.0.1:{port}")
            logger.info("Press Ctrl+C to stop the review session")
            
            # Keep the main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Stopping review session...")
                self._save_review_progress()
                self._generate_review_summary()
                
        except Exception as e:
            logger.error(f"Error starting review session: {e}")
            logger.exception(e)
    
    def _redact_secret(self, secret: str) -> str:
        """
        Redact a secret for safe display
        
        Args:
            secret: Secret to redact
            
        Returns:
            Redacted secret
        """
        if not secret:
            return ''
        
        length = len(secret)
        if length <= 8:
            return '*' * length
        elif length <= 20:
            return secret[:3] + '*' * (length - 6) + secret[-3:]
        else:
            return secret[:5] + '*' * 15 + secret[-5:]
    
    def _update_review_stats(self, review: Dict[str, Any]) -> None:
        """
        Update review statistics
        
        Args:
            review: Review data
        """
        self.stats['total_reviewed'] += 1
        
        verdict = review.get('verdict')
        if verdict == 'true_positive':
            self.stats['true_positives'] += 1
        elif verdict == 'false_positive':
            self.stats['false_positives'] += 1
        
        if review.get('requires_action'):
            self.stats['requires_action'] += 1
    
    def _save_review_progress(self) -> None:
        """Save current review progress"""
        try:
            progress_file = self.review_data_path / f"review_progress_{self.current_session['session_id']}.json"
            
            progress_data = {
                'session_id': self.current_session['session_id'],
                'started_at': self.current_session['started_at'],
                'last_saved': datetime.utcnow().isoformat(),
                'reviewed': self.current_session['reviewed'],
                'stats': self.stats
            }
            
            with open(progress_file, 'w', encoding='utf-8') as f:
                json.dump(progress_data, f, indent=2)
            
            logger.debug(f"Saved review progress to {progress_file}")
            
        except Exception as e:
            logger.error(f"Error saving review progress: {e}")
    
    def _load_review_progress(self) -> None:
        """Load previous review progress if available"""
        try:
            progress_file = self.review_data_path / f"review_progress_{self.current_session['session_id']}.json"
            
            if progress_file.exists():
                with open(progress_file, 'r', encoding='utf-8') as f:
                    progress_data = json.load(f)
                
                self.current_session['reviewed'] = progress_data.get('reviewed', {})
                self.stats = progress_data.get('stats', self.stats)
                
                logger.info(f"Loaded previous review progress: {len(self.current_session['reviewed'])} findings already reviewed")
                
        except Exception as e:
            logger.error(f"Error loading review progress: {e}")
    
    def _export_reviews_json(self) -> Optional[Path]:
        """
        Export reviews as JSON
        
        Returns:
            Path to export file
        """
        try:
            export_file = self.review_data_path / f"review_export_{self.current_session['session_id']}.json"
            
            export_data = {
                'session_id': self.current_session['session_id'],
                'exported_at': datetime.utcnow().isoformat(),
                'stats': self.stats,
                'findings': []
            }
            
            # Include only reviewed findings
            for index, review in self.current_session['reviewed'].items():
                finding = self.current_session['findings'][int(index)].copy()
                finding['manual_review'] = review
                finding['review_index'] = index
                export_data['findings'].append(finding)
            
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported reviews to {export_file}")
            return export_file
            
        except Exception as e:
            logger.error(f"Error exporting reviews as JSON: {e}")
            return None
    
    def _export_reviews_csv(self) -> Optional[Path]:
        """
        Export reviews as CSV
        
        Returns:
            Path to export file
        """
        try:
            import csv
            
            export_file = self.review_data_path / f"review_export_{self.current_session['session_id']}.csv"
            
            with open(export_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow([
                    'Type', 'Severity', 'Location', 'Verdict', 'Requires Action',
                    'Action Taken', 'Notes', 'Reviewed At', 'Reviewer'
                ])
                
                # Data rows
                for index, review in self.current_session['reviewed'].items():
                    finding = self.current_session['findings'][int(index)]
                    
                    writer.writerow([
                        finding.get('type', ''),
                        review.get('severity_override') or finding.get('severity', ''),
                        finding.get('file_path') or finding.get('url', ''),
                        review.get('verdict', ''),
                        'Yes' if review.get('requires_action') else 'No',
                        review.get('action_taken', ''),
                        review.get('notes', ''),
                        review.get('reviewed_at', ''),
                        review.get('reviewer', '')
                    ])
            
            logger.info(f"Exported reviews to {export_file}")
            return export_file
            
        except Exception as e:
            logger.error(f"Error exporting reviews as CSV: {e}")
            return None
    
    def _generate_review_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of the review session
        
        Returns:
            Review summary
        """
        try:
            summary = {
                'session_id': self.current_session['session_id'],
                'started_at': self.current_session['started_at'],
                'completed_at': datetime.utcnow().isoformat(),
                'total_findings': len(self.current_session['findings']),
                'reviewed': len(self.current_session['reviewed']),
                'unreviewed': len(self.current_session['findings']) - len(self.current_session['reviewed']),
                'statistics': self.stats,
                'critical_findings': []
            }
            
            # Identify critical findings
            for index, review in self.current_session['reviewed'].items():
                if review.get('verdict') == 'true_positive' and review.get('requires_action'):
                    finding = self.current_session['findings'][int(index)]
                    summary['critical_findings'].append({
                        'type': finding.get('type'),
                        'location': finding.get('file_path') or finding.get('url'),
                        'severity': review.get('severity_override') or finding.get('severity'),
                        'action_taken': review.get('action_taken')
                    })
            
            # Save summary
            summary_file = self.review_data_path / f"review_summary_{self.current_session['session_id']}.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2)
            
            logger.info(f"Generated review summary: {summary_file}")
            return summary
            
        except Exception as e:
            logger.error(f"Error generating review summary: {e}")
            return {}
    
    def get_review_template(self) -> str:
        """
        Get HTML template for review interface
        
        Returns:
            HTML template string
        """
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>Secret Scanner - Manual Review Interface</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: #2c3e50;
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
        }
        header h1 { margin: 0 20px; }
        .stats-bar {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-around;
        }
        .stat-item {
            text-align: center;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }
        .finding-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .finding-type {
            font-weight: bold;
            color: #2c3e50;
        }
        .severity {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #95a5a6; color: white; }
        .finding-details {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
            font-family: monospace;
            font-size: 0.9em;
        }
        .review-actions {
            margin-top: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
        }
        .btn-primary { background: #3498db; color: white; }
        .btn-success { background: #27ae60; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-secondary { background: #95a5a6; color: white; }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .notes-input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-top: 10px;
            font-family: inherit;
        }
        .navigation {
            display: flex;
            justify-content: space-between;
            margin-top: 30px;
        }
        .progress-bar {
            background: #ecf0f1;
            border-radius: 4px;
            height: 8px;
            margin: 20px 0;
            overflow: hidden;
        }
        .progress-fill {
            background: #27ae60;
            height: 100%;
            transition: width 0.3s;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 8px;
            max-width: 500px;
            width: 90%;
        }
        .reviewed-badge {
            background: #27ae60;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔍 Secret Scanner - Manual Review Interface</h1>
        </div>
    </header>
    
    <div class="container">
        <div class="stats-bar">
            <div class="stat-item">
                <div class="stat-value" id="total-findings">0</div>
                <div>Total Findings</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="reviewed-count">0</div>
                <div>Reviewed</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="true-positives">0</div>
                <div>True Positives</div>
            </div>
            <div class="stat-item">
                <div class="stat-value" id="false-positives">0</div>
                <div>False Positives</div>
            </div>
        </div>
        
        <div class="progress-bar">
            <div class="progress-fill" id="progress-fill"></div>
        </div>
        
        <div id="findings-container">
            <!-- Findings will be loaded here -->
        </div>
        
        <div class="navigation">
            <button class="btn btn-secondary" onclick="loadPreviousBatch()">← Previous</button>
            <button class="btn btn-primary" onclick="exportResults()">Export Results</button>
            <button class="btn btn-secondary" onclick="loadNextBatch()">Next →</button>
        </div>
    </div>
    
    <div class="modal" id="export-modal">
        <div class="modal-content">
            <h3>Export Review Results</h3>
            <p>Choose export format:</p>
            <div style="margin-top: 20px;">
                <button class="btn btn-primary" onclick="doExport('json')">Export as JSON</button>
                <button class="btn btn-success" onclick="doExport('csv')">Export as CSV</button>
                <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentBatch = 0;
        const batchSize = 10;
        let sessionData = {};
        let stats = { true_positives: 0, false_positives: 0 };
        
        // Initialize
        async function init() {
            await loadSession();
            await loadStats();
            await loadFindings();
        }
        
        async function loadSession() {
            const response = await fetch('/api/session');
            sessionData = await response.json();
            updateUI();
        }
        
        async function loadStats() {
            const response = await fetch('/api/stats');
            stats = await response.json();
            updateUI();
        }
        
        async function loadFindings() {
            const response = await fetch(`/api/findings/batch?start=${currentBatch * batchSize}&limit=${batchSize}`);
            const data = await response.json();
            
            const container = document.getElementById('findings-container');
            container.innerHTML = '';
            
            data.findings.forEach(finding => {
                container.appendChild(createFindingCard(finding));
            });
        }
        
        function createFindingCard(finding) {
            const card = document.createElement('div');
            card.className = 'finding-card';
            card.innerHTML = `
                <div class="finding-header">
                    <div>
                        <span class="finding-type">${finding.type}</span>
                        ${finding.reviewed ? '<span class="reviewed-badge">Reviewed</span>' : ''}
                    </div>
                    <span class="severity severity-${finding.severity}">${finding.severity}</span>
                </div>
                <div class="finding-details">
                    <strong>Location:</strong> ${finding.file_path || finding.url || 'Unknown'}<br>
                    ${finding.line_number ? `<strong>Line:</strong> ${finding.line_number}<br>` : ''}
                    <strong>Secret:</strong> ${finding.secret_display || '[REDACTED]'}<br>
                    ${finding.verified !== undefined ? `<strong>Auto-validated:</strong> ${finding.verified ? 'Yes' : 'No'}<br>` : ''}
                </div>
                <div class="review-actions">
                    <button class="btn btn-success" onclick="reviewFinding(${finding.index}, 'true_positive')">
                        ✓ True Positive
                    </button>
                    <button class="btn btn-danger" onclick="reviewFinding(${finding.index}, 'false_positive')">
                        ✗ False Positive
                    </button>
                    <button class="btn btn-secondary" onclick="reviewFinding(${finding.index}, 'unsure')">
                        ? Unsure
                    </button>
                </div>
                <textarea class="notes-input" id="notes-${finding.index}" 
                    placeholder="Add notes about this finding..."></textarea>
            `;
            return card;
        }
        
        async function reviewFinding(index, verdict) {
            const notes = document.getElementById(`notes-${index}`).value;
            const requiresAction = verdict === 'true_positive' && confirm('Does this finding require immediate action?');
            
            const reviewData = {
                verdict: verdict,
                notes: notes,
                requires_action: requiresAction,
                reviewer: 'User'  // In a real app, get from auth
            };
            
            if (requiresAction) {
                reviewData.action_taken = prompt('What action was taken?') || '';
            }
            
            const response = await fetch(`/api/finding/${index}/review`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reviewData)
            });
            
            if (response.ok) {
                await loadSession();
                await loadStats();
                await loadFindings();
            }
        }
        
        function updateUI() {
            document.getElementById('total-findings').textContent = sessionData.total_findings || 0;
            document.getElementById('reviewed-count').textContent = sessionData.reviewed || 0;
            document.getElementById('true-positives').textContent = stats.true_positives || 0;
            document.getElementById('false-positives').textContent = stats.false_positives || 0;
            
            // Update progress bar
            const progress = (sessionData.reviewed / sessionData.total_findings) * 100 || 0;
            document.getElementById('progress-fill').style.width = progress + '%';
        }
        
        function loadPreviousBatch() {
            if (currentBatch > 0) {
                currentBatch--;
                loadFindings();
            }
        }
        
        function loadNextBatch() {
            if ((currentBatch + 1) * batchSize < sessionData.total_findings) {
                currentBatch++;
                loadFindings();
            }
        }
        
        function exportResults() {
            document.getElementById('export-modal').style.display = 'flex';
        }
        
        function closeModal() {
            document.getElementById('export-modal').style.display = 'none';
        }
        
        async function doExport(format) {
            window.location.href = `/api/export?format=${format}`;
            closeModal();
        }
        
        // Initialize on load
        document.addEventListener('DOMContentLoaded', init);
        
        // Auto-save progress every 30 seconds
        setInterval(async () => {
            await loadSession();
        }, 30000);
    </script>
</body>
</html>
        '''