#!/usr/bin/env python3
"""
EDR Server Main Entry Point
Chạy file này để khởi động EDR Server
"""

import os
import sys
import time
import threading
import logging
import signal
import atexit
from datetime import datetime
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS

# Import configurations và utils
from config import SERVER_SETTINGS, LOGGING_CONFIG
from utils.logger import setup_logging
from services.socketio_handler import SocketIOHandler
from database.connection import DatabaseConnection

# Import API blueprints
from api.agents import agents_api
from api.alerts import alerts_api
from api.rules import rules_api
from api.dashboard import dashboard_api
from api.logs import logs_api

class EDRServer:
    def __init__(self):
        self.app = None
        self.socketio = None
        self.socketio_handler = None
        self.shutdown_event = threading.Event()
        self.background_threads = []
        
    def create_app(self):
        """Tạo Flask application"""
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'edr_secret_key_2024'
        
        # Enable CORS
        CORS(self.app, origins="*")
        
        # Initialize SocketIO
        self.socketio = SocketIO(
            self.app,
            cors_allowed_origins="*",
            async_mode='threading',
            ping_timeout=60,
            ping_interval=25,
            logger=False,
            engineio_logger=False
        )
        
        return self.app
    
    def register_blueprints(self):
        """Đăng ký các API blueprints"""
        try:
            self.app.register_blueprint(agents_api)
            self.app.register_blueprint(alerts_api)
            self.app.register_blueprint(rules_api)
            self.app.register_blueprint(dashboard_api)
            self.app.register_blueprint(logs_api)
            logging.info("All API blueprints registered successfully")
        except Exception as e:
            logging.error(f"Error registering blueprints: {e}")
            raise
    
    def setup_socketio_handlers(self):
        """Setup SocketIO event handlers"""
        try:
            self.socketio_handler = SocketIOHandler(self.socketio)
            self.socketio_handler.register_handlers()
            logging.info("SocketIO handlers registered successfully")
        except Exception as e:
            logging.error(f"Error setting up SocketIO handlers: {e}")
            raise
    
    def start_background_tasks(self):
        """Khởi động các background tasks"""
        try:
            # Agent cleanup task
            cleanup_thread = threading.Thread(
                target=self._agent_cleanup_worker,
                daemon=True,
                name="AgentCleanup"
            )
            cleanup_thread.start()
            self.background_threads.append(cleanup_thread)
            
            # Database maintenance task
            maintenance_thread = threading.Thread(
                target=self._database_maintenance_worker,
                daemon=True,
                name="DatabaseMaintenance"
            )
            maintenance_thread.start()
            self.background_threads.append(maintenance_thread)
            
            logging.info("Background tasks started successfully")
            
        except Exception as e:
            logging.error(f"Error starting background tasks: {e}")
            raise
    
    def _agent_cleanup_worker(self):
        """Worker để dọn dẹp các agent offline"""
        from database.agents import AgentDB
        
        while not self.shutdown_event.is_set():
            try:
                agent_db = AgentDB()
                offline_count = agent_db.cleanup_offline_agents(5)  # 5 minutes threshold
                
                if offline_count > 0:
                    logging.info(f"Marked {offline_count} agents as offline")
                
            except Exception as e:
                logging.error(f"Error in agent cleanup worker: {e}")
            
            # Sleep for 60 seconds
            for _ in range(60):
                if self.shutdown_event.is_set():
                    break
                time.sleep(1)
    
    def _database_maintenance_worker(self):
        """Worker để bảo trì database"""
        from database.logs import LogDB
        from database.alerts import AlertDB
        
        while not self.shutdown_event.is_set():
            try:
                current_hour = datetime.now().hour
                
                # Chạy maintenance vào 2h sáng
                if current_hour == 2:
                    logging.info("Starting database maintenance...")
                    
                    # Cleanup old logs (older than 30 days)
                    log_db = LogDB()
                    log_db.cleanup_old_logs(30)
                    
                    # Cleanup old resolved alerts (older than 90 days)
                    alert_db = AlertDB()
                    alert_db.cleanup_old_alerts(90)
                    
                    logging.info("Database maintenance completed")
                    
                    # Sleep until next day
                    time.sleep(3600)  # 1 hour
                
            except Exception as e:
                logging.error(f"Error in database maintenance worker: {e}")
            
            # Sleep for 1 hour
            for _ in range(3600):
                if self.shutdown_event.is_set():
                    break
                time.sleep(1)
    
    def setup_routes(self):
        """Setup basic routes"""
        @self.app.route('/')
        def index():
            return {
                "message": "EDR Server is running",
                "version": "2.0",
                "timestamp": datetime.now().isoformat(),
                "status": "healthy",
                "endpoints": {
                    "agents": "/agents",
                    "alerts": "/alerts", 
                    "rules": "/rules",
                    "dashboard": "/dashboard",
                    "logs": "/logs"
                }
            }
        
        @self.app.route('/health')
        def health_check():
            """Health check endpoint"""
            try:
                # Test database connection
                db = DatabaseConnection()
                db.connect()
                db_status = "healthy"
                db.close()
            except Exception as e:
                db_status = f"error: {str(e)}"
            
            return {
                "status": "healthy" if db_status == "healthy" else "degraded",
                "timestamp": datetime.now().isoformat(),
                "components": {
                    "database": db_status,
                    "socketio": "healthy",
                    "api": "healthy"
                },
                "uptime": time.time() - self.start_time if hasattr(self, 'start_time') else 0
            }
    
    def setup_error_handlers(self):
        """Setup error handlers"""
        @self.app.errorhandler(404)
        def not_found(error):
            return {"error": "Endpoint not found", "code": 404}, 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            logging.error(f"Internal server error: {error}")
            return {"error": "Internal server error", "code": 500}, 500
        
        @self.app.errorhandler(Exception)
        def handle_exception(e):
            logging.error(f"Unhandled exception: {e}", exc_info=True)
            return {"error": "Unexpected error occurred", "code": 500}, 500
    
    def test_database_connection(self):
        """Test database connection"""
        try:
            db = DatabaseConnection()
            success = db.connect()
            if success:
                logging.info("Database connection test: SUCCESS")
                db.close()
                return True
            else:
                logging.error("Database connection test: FAILED")
                return False
        except Exception as e:
            logging.error(f"Database connection test failed: {e}")
            return False
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            logging.info("Starting server cleanup...")
            
            # Set shutdown event
            self.shutdown_event.set()
            
            # Wait for background threads to finish
            for thread in self.background_threads:
                if thread.is_alive():
                    thread.join(timeout=5)
            
            # Cleanup SocketIO handler
            if self.socketio_handler:
                self.socketio_handler.cleanup()
            
            logging.info("Server cleanup completed")
            
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logging.info(f"Received signal {signum}, shutting down...")
        self.cleanup()
        sys.exit(0)
    
    def run(self):
        """Main server run method"""
        try:
            # Setup logging
            setup_logging()
            self.start_time = time.time()
            
            logging.info("="*60)
            logging.info("🚀 Starting EDR Server")
            logging.info("="*60)
            
            # Test database connection first
            if not self.test_database_connection():
                logging.error("❌ Database connection failed. Please check your database configuration.")
                sys.exit(1)
            
            # Create Flask app
            self.create_app()
            logging.info("✅ Flask application created")
            
            # Setup routes and error handlers
            self.setup_routes()
            self.setup_error_handlers()
            logging.info("✅ Routes and error handlers configured")
            
            # Register API blueprints
            self.register_blueprints()
            logging.info("✅ API blueprints registered")
            
            # Setup SocketIO handlers
            self.setup_socketio_handlers()
            logging.info("✅ SocketIO handlers configured")
            
            # Start background tasks
            self.start_background_tasks()
            logging.info("✅ Background tasks started")
            
            # Setup signal handlers
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            atexit.register(self.cleanup)
            
            # Print server info
            host = SERVER_SETTINGS['host']
            port = SERVER_SETTINGS['port']
            
            logging.info("="*60)
            logging.info("🎉 EDR Server started successfully!")
            logging.info(f"📍 Server URL: http://{host}:{port}")
            logging.info(f"🔌 SocketIO URL: http://{host}:{port}")
            logging.info(f"📊 Health Check: http://{host}:{port}/health")
            logging.info("="*60)
            
            # Start the server
            self.socketio.run(
                self.app,
                host=host,
                port=port,
                debug=SERVER_SETTINGS.get('debug', False),
                use_reloader=False
            )
            
        except KeyboardInterrupt:
            logging.info("Server interrupted by user")
        except Exception as e:
            logging.error(f"❌ Server startup failed: {e}", exc_info=True)
            sys.exit(1)
        finally:
            self.cleanup()

def main():
    """Main entry point"""
    print("🔧 Initializing EDR Server...")
    server = EDRServer()
    server.run()

if __name__ == '__main__':
    main()