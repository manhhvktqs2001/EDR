"""
Rules API Endpoints
Xử lý tất cả API calls liên quan đến rules
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import logging
from database.rules import RuleDB
from utils.helpers import create_success_response, create_error_response, paginate_results, safe_int

rules_api = Blueprint('rules_api', __name__, url_prefix='/rules')
logger = logging.getLogger(__name__)

@rules_api.route('', methods=['GET'])
def get_rules():
    """Lấy danh sách rules với filtering"""
    try:
        rule_db = RuleDB()
        
        # Extract query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        rule_type = request.args.get('type')
        severity = request.args.get('severity')
        os_type = request.args.get('os_type')
        is_active = request.args.get('is_active')
        search = request.args.get('search')
        
        # Get rules based on filters
        if rule_type:
            rules = rule_db.get_rules_by_type(rule_type)
        elif severity:
            rules = rule_db.get_rules_by_severity(severity)
        elif search:
            rules = rule_db.search_rules(search)
        else:
            rules = rule_db.get_all_rules()
        
        # Apply additional filters
        if os_type:
            rules = [r for r in rules if r.get('OSType') == os_type or r.get('OSType') == 'All']
        
        if is_active is not None:
            active_filter = is_active.lower() == 'true'
            rules = [r for r in rules if bool(r.get('IsActive')) == active_filter]
        
        # Paginate results
        paginated = paginate_results(rules, page, per_page)
        
        return jsonify(create_success_response(paginated)), 200
        
    except Exception as e:
        logger.error(f"Error getting rules: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/<int:rule_id>', methods=['GET'])
def get_rule(rule_id):
    """Lấy thông tin chi tiết rule"""
    try:
        rule_db = RuleDB()
        rule = rule_db.get_rule_by_id(rule_id)
        
        if not rule:
            return jsonify(create_error_response("Rule not found")), 404
        
        return jsonify(create_success_response(rule)), 200
        
    except Exception as e:
        logger.error(f"Error getting rule {rule_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('', methods=['POST'])
def create_rule():
    """Tạo rule mới"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(create_error_response("No data provided")), 400
        
        # Validate required fields
        required_fields = ['rule_name', 'rule_type', 'severity', 'description']
        for field in required_fields:
            if field not in data:
                return jsonify(create_error_response(f"Missing required field: {field}")), 400
        
        rule_db = RuleDB()
        
        # Validate rule data
        validation = rule_db.validate_rule_data(data)
        if not validation['valid']:
            return jsonify(create_error_response(f"Validation failed: {'; '.join(validation['errors'])}")), 400
        
        success = rule_db.create_rule(data)
        
        if success:
            return jsonify(create_success_response(
                None, 
                f"Rule '{data['rule_name']}' created successfully"
            )), 201
        else:
            return jsonify(create_error_response("Failed to create rule")), 500
            
    except Exception as e:
        logger.error(f"Error creating rule: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/<int:rule_id>', methods=['PUT'])
def update_rule(rule_id):
    """Cập nhật rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(create_error_response("No data provided")), 400
        
        rule_db = RuleDB()
        success = rule_db.update_rule(rule_id, data)
        
        if success:
            return jsonify(create_success_response(
                None, 
                f"Rule {rule_id} updated successfully"
            )), 200
        else:
            return jsonify(create_error_response("Failed to update rule")), 500
            
    except Exception as e:
        logger.error(f"Error updating rule {rule_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """Xóa rule"""
    try:
        rule_db = RuleDB()
        success = rule_db.delete_rule(rule_id)
        
        if success:
            return jsonify(create_success_response(
                None, 
                f"Rule {rule_id} deleted successfully"
            )), 200
        else:
            return jsonify(create_error_response("Failed to delete rule")), 500
            
    except Exception as e:
        logger.error(f"Error deleting rule {rule_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/statistics', methods=['GET'])
def get_rules_statistics():
    """Lấy thống kê rules"""
    try:
        rule_db = RuleDB()
        stats = rule_db.get_rules_statistics()
        
        return jsonify(create_success_response(stats)), 200
        
    except Exception as e:
        logger.error(f"Error getting rules statistics: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/global', methods=['GET'])
def get_global_rules():
    """Lấy global rules"""
    try:
        os_type = request.args.get('os_type')
        
        rule_db = RuleDB()
        rules = rule_db.get_global_rules(os_type)
        
        return jsonify(create_success_response({
            'rules': rules,
            'count': len(rules),
            'os_type': os_type or 'All'
        })), 200
        
    except Exception as e:
        logger.error(f"Error getting global rules: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/validate', methods=['POST'])
def validate_rule():
    """Validate rule data"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(create_error_response("No data provided")), 400
        
        rule_db = RuleDB()
        validation = rule_db.validate_rule_data(data)
        
        return jsonify(create_success_response(validation)), 200
        
    except Exception as e:
        logger.error(f"Error validating rule: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/export', methods=['GET'])
def export_rules():
    """Export rules"""
    try:
        rule_ids = request.args.getlist('rule_ids')
        if rule_ids:
            rule_ids = [int(rid) for rid in rule_ids]
        
        rule_db = RuleDB()
        rules_data = rule_db.export_rules(rule_ids)
        
        return jsonify(create_success_response({
            'rules': rules_data,
            'count': len(rules_data),
            'exported_at': datetime.now().isoformat()
        })), 200
        
    except Exception as e:
        logger.error(f"Error exporting rules: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/import', methods=['POST'])
def import_rules():
    """Import rules"""
    try:
        data = request.get_json()
        if not data or 'rules' not in data:
            return jsonify(create_error_response("Rules data is required")), 400
        
        rules_data = data['rules']
        if not isinstance(rules_data, list):
            return jsonify(create_error_response("Rules must be a list")), 400
        
        rule_db = RuleDB()
        result = rule_db.import_rules(rules_data)
        
        return jsonify(create_success_response(result)), 200
        
    except Exception as e:
        logger.error(f"Error importing rules: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/<int:rule_id>/clone', methods=['POST'])
def clone_rule(rule_id):
    """Clone rule"""
    try:
        data = request.get_json() or {}
        new_name = data.get('new_name', f'Copy of Rule {rule_id}')
        
        rule_db = RuleDB()
        success = rule_db.clone_rule(rule_id, new_name)
        
        if success:
            return jsonify(create_success_response(
                None,
                f"Rule {rule_id} cloned successfully as '{new_name}'"
            )), 201
        else:
            return jsonify(create_error_response("Failed to clone rule")), 500
            
    except Exception as e:
        logger.error(f"Error cloning rule {rule_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/bulk/update', methods=['PUT'])
def bulk_update_rules():
    """Bulk update rules"""
    try:
        data = request.get_json()
        if not data or 'updates' not in data:
            return jsonify(create_error_response("Updates data is required")), 400
        
        updates = data['updates']
        if not isinstance(updates, list):
            return jsonify(create_error_response("Updates must be a list")), 400
        
        rule_db = RuleDB()
        result = rule_db.bulk_update_rules(updates)
        
        return jsonify(create_success_response(result)), 200
        
    except Exception as e:
        logger.error(f"Error in bulk update rules: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/<int:rule_id>/usage', methods=['GET'])
def get_rule_usage(rule_id):
    """Lấy thống kê sử dụng rule"""
    try:
        rule_db = RuleDB()
        stats = rule_db.get_rule_usage_statistics(rule_id)
        
        if not stats:
            return jsonify(create_error_response("Rule not found")), 404
        
        return jsonify(create_success_response(stats)), 200
        
    except Exception as e:
        logger.error(f"Error getting rule usage {rule_id}: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/effectiveness', methods=['GET'])
def get_rules_effectiveness():
    """Lấy phân tích hiệu quả rules"""
    try:
        days = int(request.args.get('days', 7))
        
        from rules.rule_engine import RuleEngine
        rule_engine = RuleEngine()
        effectiveness = rule_engine.get_rule_effectiveness(days)
        
        return jsonify(create_success_response(effectiveness)), 200
        
    except Exception as e:
        logger.error(f"Error getting rules effectiveness: {e}")
        return jsonify(create_error_response(str(e))), 500

@rules_api.route('/optimize', methods=['GET'])
def optimize_rules():
    """Lấy khuyến nghị tối ưu rules"""
    try:
        from rules.rule_engine import RuleEngine
        rule_engine = RuleEngine()
        optimizations = rule_engine.optimize_rules()
        
        return jsonify(create_success_response(optimizations)), 200
        
    except Exception as e:
        logger.error(f"Error getting rule optimizations: {e}")
        return jsonify(create_error_response(str(e))), 500