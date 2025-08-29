import razorpay
from typing import Dict, Any, List
from datetime import datetime
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class RazorpayService:
    def __init__(self, key_id: str = None, key_secret: str = None):
        self.key_id = key_id or current_app.config.get('RAZORPAY_KEY_ID')
        self.key_secret = key_secret or current_app.config.get('RAZORPAY_KEY_SECRET')
        self.client = razorpay.Client(auth=(self.key_id, self.key_secret))
    
    def create_payment_order(self, amount: int, currency: str = 'INR', 
                           notes: Dict[str, str] = None, receipt: str = None) -> Dict[str, Any]:
        """Create payment order for political party"""
        try:
            data = {
                "amount": amount * 100,  # Razorpay expects amount in paise
                "currency": currency,
                "notes": notes or {},
                "receipt": receipt or f"receipt_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            }
            
            order = self.client.order.create(data=data)
            logger.info(f"Payment order created: {order['id']}")
            
            return {
                'success': True,
                'order_id': order['id'],
                'amount': order['amount'],
                'currency': order['currency'],
                'receipt': order['receipt'],
                'status': order['status']
            }
            
        except Exception as e:
            logger.error(f"Payment order creation error: {e}")
            return {
                'success': False,
                'error': 'Failed to create payment order',
                'details': str(e)
            }
    
    def verify_payment_signature(self, payment_id: str, order_id: str, 
                               signature: str) -> bool:
        """Verify payment signature"""
        try:
            self.client.utility.verify_payment_signature({
                'razorpay_payment_id': payment_id,
                'razorpay_order_id': order_id,
                'razorpay_signature': signature
            })
            logger.info(f"Payment signature verified for: {payment_id}")
            return True
        except Exception as e:
            logger.error(f"Payment signature verification failed: {e}")
            return False
    
    def get_payment_details(self, payment_id: str) -> Dict[str, Any]:
        """Get payment details from Razorpay"""
        try:
            payment = self.client.payment.fetch(payment_id)
            logger.info(f"Payment details retrieved: {payment_id}")
            
            return {
                'success': True,
                'payment_id': payment['id'],
                'order_id': payment['order_id'],
                'amount': payment['amount'],
                'currency': payment['currency'],
                'status': payment['status'],
                'method': payment['method'],
                'email': payment.get('email'),
                'contact': payment.get('contact'),
                'created_at': payment['created_at']
            }
            
        except Exception as e:
            logger.error(f"Get payment details error: {e}")
            return {
                'success': False,
                'error': 'Failed to get payment details',
                'details': str(e)
            }
    
    def create_payout(self, account_number: str, ifsc_code: str, 
                     amount: int, name: str, purpose: str = "volunteer_payment") -> Dict[str, Any]:
        """Create payout to volunteer's bank account"""
        try:
            data = {
                "account_number": account_number,
                "ifsc": ifsc_code,
                "amount": amount * 100,  # Convert to paise
                "currency": "INR",
                "mode": "IMPS",
                "purpose": purpose,
                "fund_account": {
                    "account_type": "savings",
                    "contact": {
                        "name": name,
                        "email": "volunteer@example.com",
                        "contact": "9999999999"
                    }
                }
            }
            
            payout = self.client.payout.create(data=data)
            logger.info(f"Payout created: {payout['id']}")
            
            return {
                'success': True,
                'payout_id': payout['id'],
                'amount': payout['amount'],
                'status': payout['status'],
                'utr': payout.get('utr'),
                'created_at': payout['created_at']
            }
            
        except Exception as e:
            logger.error(f"Payout creation error: {e}")
            return {
                'success': False,
                'error': 'Failed to create payout',
                'details': str(e)
            }
    
    def get_payout_details(self, payout_id: str) -> Dict[str, Any]:
        """Get payout details from Razorpay"""
        try:
            payout = self.client.payout.fetch(payout_id)
            logger.info(f"Payout details retrieved: {payout_id}")
            
            return {
                'success': True,
                'payout_id': payout['id'],
                'amount': payout['amount'],
                'status': payout['status'],
                'utr': payout.get('utr'),
                'created_at': payout['created_at'],
                'processed_at': payout.get('processed_at')
            }
            
        except Exception as e:
            logger.error(f"Get payout details error: {e}")
            return {
                'success': False,
                'error': 'Failed to get payout details',
                'details': str(e)
            }
    
    def refund_payment(self, payment_id: str, amount: int = None, 
                      notes: Dict[str, str] = None) -> Dict[str, Any]:
        """Refund payment"""
        try:
            data = {
                "payment_id": payment_id,
                "notes": notes or {}
            }
            
            if amount:
                data["amount"] = amount * 100  # Convert to paise
            
            refund = self.client.payment.refund(data=data)
            logger.info(f"Payment refunded: {refund['id']}")
            
            return {
                'success': True,
                'refund_id': refund['id'],
                'payment_id': refund['payment_id'],
                'amount': refund['amount'],
                'status': refund['status'],
                'created_at': refund['created_at']
            }
            
        except Exception as e:
            logger.error(f"Payment refund error: {e}")
            return {
                'success': False,
                'error': 'Failed to refund payment',
                'details': str(e)
            }
    
    def get_settlements(self, from_date: str = None, to_date: str = None) -> Dict[str, Any]:
        """Get settlement details"""
        try:
            data = {}
            if from_date:
                data["from"] = from_date
            if to_date:
                data["to"] = to_date
            
            settlements = self.client.settlement.all(data=data)
            logger.info(f"Settlements retrieved: {len(settlements['items'])} items")
            
            return {
                'success': True,
                'settlements': settlements['items'],
                'count': len(settlements['items'])
            }
            
        except Exception as e:
            logger.error(f"Get settlements error: {e}")
            return {
                'success': False,
                'error': 'Failed to get settlements',
                'details': str(e)
            }

class CommissionService:
    def __init__(self):
        self.platform_commission_rate = current_app.config.get('PLATFORM_COMMISSION_RATE', 0.05)
        self.payment_gateway_fee_rate = current_app.config.get('PAYMENT_GATEWAY_FEE_RATE', 0.02)
        self.volunteer_payout_fee_rate = current_app.config.get('VOLUNTEER_PAYOUT_FEE_RATE', 0.01)
    
    def calculate_commission(self, payment_amount: int) -> Dict[str, Any]:
        """Calculate commission breakdown"""
        try:
            amount = payment_amount
            
            platform_fee = int(amount * self.platform_commission_rate)
            payment_gateway_fee = int(amount * self.payment_gateway_fee_rate)
            total_commission = platform_fee + payment_gateway_fee
            
            volunteer_amount = amount - total_commission
            
            return {
                'success': True,
                'total_amount': amount,
                'platform_fee': platform_fee,
                'payment_gateway_fee': payment_gateway_fee,
                'total_commission': total_commission,
                'volunteer_amount': volunteer_amount,
                'commission_percentage': (total_commission / amount) * 100 if amount > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Commission calculation error: {e}")
            return {
                'success': False,
                'error': 'Failed to calculate commission',
                'details': str(e)
            }
    
    def process_volunteer_payout(self, volunteer_id: str, amount: int) -> Dict[str, Any]:
        """Process volunteer payout with commission deduction"""
        try:
            commission_calc = self.calculate_commission(amount)
            
            if not commission_calc['success']:
                return commission_calc
            
            # Deduct payout fee
            payout_fee = int(commission_calc['volunteer_amount'] * self.volunteer_payout_fee_rate)
            final_payout = commission_calc['volunteer_amount'] - payout_fee
            
            return {
                'success': True,
                'volunteer_id': volunteer_id,
                'original_amount': amount,
                'payout_amount': final_payout,
                'payout_fee': payout_fee,
                'total_deductions': commission_calc['total_commission'] + payout_fee,
                'commission_breakdown': commission_calc
            }
            
        except Exception as e:
            logger.error(f"Volunteer payout processing error: {e}")
            return {
                'success': False,
                'error': 'Failed to process volunteer payout',
                'details': str(e)
            }
    
    def get_commission_summary(self, payments: List[Dict]) -> Dict[str, Any]:
        """Get commission summary for multiple payments"""
        try:
            total_amount = 0
            total_platform_fee = 0
            total_payment_gateway_fee = 0
            total_commission = 0
            
            for payment in payments:
                amount = payment.get('amount', 0)
                commission_calc = self.calculate_commission(amount)
                
                if commission_calc['success']:
                    total_amount += amount
                    total_platform_fee += commission_calc['platform_fee']
                    total_payment_gateway_fee += commission_calc['payment_gateway_fee']
                    total_commission += commission_calc['total_commission']
            
            return {
                'success': True,
                'total_amount': total_amount,
                'total_platform_fee': total_platform_fee,
                'total_payment_gateway_fee': total_payment_gateway_fee,
                'total_commission': total_commission,
                'commission_percentage': (total_commission / total_amount) * 100 if total_amount > 0 else 0,
                'payment_count': len(payments)
            }
            
        except Exception as e:
            logger.error(f"Commission summary error: {e}")
            return {
                'success': False,
                'error': 'Failed to calculate commission summary',
                'details': str(e)
            }
