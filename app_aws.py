                                                                                                                                                      # app_aws.py - COMPLETE MARKETING PLATFORM WITH DYNAMODB + SNS
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import boto3
from boto3.dynamodb.conditions import Key
from datetime import datetime
import json
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'aws-ai-marketing-platform-2026-super-secret-key'

#  AWS CONFIGURATION
REGION = 'us-east-1'
dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)

#  DYNAMODB TABLES (Create these 4 tables manually)
users_table = dynamodb.Table('Users')
admin_table = dynamodb.Table('Admin')
products_table = dynamodb.Table('Products')
campaigns_table = dynamodb.Table('Campaigns')

#  SNS TOPIC (Create SNS topic and get ARN)
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:marketing-notifications'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_sns_notification(subject, message):
    """Send SNS notification for admin alerts"""
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        print(f"✅ SNS Notification sent: {subject}")
    except Exception as e:
        print(f"❌ SNS Error: {e}")

#  HOME PAGE & PRODUCT TRACKING
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.json
        user_email = session.get('user_email', data.get('user_email', 'guest'))
        product_name = data.get('product_name')
        category = data.get('category', 'general')
        action = data.get('action', 'search')
        
        # Track product interaction
        products_table.update_item(
            Key={'category': category},
            UpdateExpression="ADD interactions.#user :count SET #prod = list_append(if_not_exists(#prod, :empty_list), :new_item)",
            ExpressionAttributeNames={
                '#user': user_email,
                '#prod': 'products',
                'interactions': 'interactions'
            },
            ExpressionAttributeValues={
                ':count': 1,
                ':new_item': [product_name],
                ':empty_list': []
            }
        )
        
        # Send SNS notification to admin
        send_sns_notification(
            f"Product {action.title()} - {product_name}",
            f"User: {user_email}\nProduct: {product_name}\nCategory: {category}\nAction: {action}\nTime: {datetime.now().isoformat()}"
        )
        
        return jsonify({'status': 'success', 'message': f'Tracked {product_name}'})
    
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

#  USER AUTHENTICATION
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])
        name = request.form['name']
        
        # Check if user exists
        response = users_table.get_item(Key={'email': email})
        if 'Item' in response:
            flash('User already exists!')
            return render_template('signup.html')
        
        # Create user
        users_table.put_item(Item={
            'email': email,
            'password': password,
            'name': name,
            'created_at': datetime.now().isoformat(),
            'role': 'user'
        })
        
        send_sns_notification("New User Signup", f"User {name} ({email}) registered!")
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])
        
        response = users_table.get_item(Key={'email': email})
        if 'Item' in response and response['Item']['password'] == password:
            session['user_email'] = email
            session['user_name'] = response['Item']['name']
            return redirect(url_for('home'))
        
        flash('Invalid credentials!')
        return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('index'))

# ADMIN ROUTES
@app.route('/admin_login.html')
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])
        
        response = admin_table.get_item(Key={'email': email})
        if 'Item' in response and response['Item']['password'] == password:
            session['admin_email'] = email
            session['admin_name'] = response['Item'].get('name', 'Admin')
            return redirect(url_for('admin_home'))
        
        flash('Invalid admin credentials!')
        return render_template('admin_login.html')
    
    return render_template('admin_login.html')

@app.route('/admin_home')
@app.route('/admin_home.html')
def admin_home():
    if 'admin_email' not in session:
        return redirect(url_for('admin_login'))
    
    # Get dashboard metrics
    users = users_table.scan()['Items']
    campaigns = campaigns_table.scan()['Items']
    products_response = products_table.scan()
    products = products_response['Items']
    
    total_users = len(users)
    total_campaigns = len(campaigns)
    total_products = len(products)
    active_campaigns = len([c for c in campaigns if c.get('status') == 'active'])
    
    # Calculate revenue/messages from product interactions
    total_messages = sum(p.get('interactions', {}).get('total', {}).get('count', 0) for p in products)
    total_revenue = total_campaigns * 1000  # Simulated
    
    return render_template('admin_home.html', 
                         total_users=total_users,
                         total_campaigns=total_campaigns,
                         total_products=total_products,
                         active_campaigns=active_campaigns,
                         total_messages=total_messages,
                         total_revenue=total_revenue)

@app.route('/dashboard.html')
@app.route('/dashboard')
def dashboard():
    if 'admin_email' not in session:
        return redirect(url_for('admin_login'))
    
    # Get real-time data from DynamoDB
    users = len(users_table.scan()['Items'])
    campaigns = campaigns_table.scan()['Items']
    products = products_table.scan()['Items']
    
    return render_template('dashboard.html',
                         total_users=users,
                         total_campaigns=len(campaigns),
                         active_campaigns=len([c for c in campaigns if c.get('status') == 'active']),
                         total_revenue=0,  # Calculate from campaigns
                         messages_sent=sum(p.get('messages_sent', 0) for p in products),
                         conversion_rate=0)  # Calculate from analytics

#  CAMPAIGN MANAGEMENT
@app.route('/campaign.html')
@app.route('/campaign')
def campaign():
    if 'admin_email' not in session:
        return redirect(url_for('admin_login'))
    
    campaigns = campaigns_table.scan()['Items']
    return render_template('campaign.html', campaigns=campaigns)

@app.route('/campaign_history.html')
@app.route('/campaign_history')
def campaign_history():
    if 'admin_email' not in session:
        return redirect(url_for('admin_login'))
    
    all_campaigns = campaigns_table.scan()['Items']
    return render_template('campaign_history.html', campaigns=all_campaigns)

@app.route('/create_campaign', methods=['POST'])
def create_campaign():
    if 'admin_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    campaign_id = f"camp_{int(datetime.now().timestamp())}"
    
    campaigns_table.put_item(Item={
        'campaign_id': campaign_id,
        'name': data['name'],
        'target_product': data['product'],
        'target_users': data.get('users', []),
        'status': 'active',
        'budget': data.get('budget', 0),
        'created_at': datetime.now().isoformat(),
        'created_by': session['admin_email'],
        'metrics': {'sent': 0, 'clicks': 0, 'conversions': 0}
    })
    
    # Notify all users via SNS
    send_sns_notification(
        f"New Campaign: {data['name']}",
        f"Campaign launched targeting {len(data.get('users', []))} users for {data['product']}"
    )
    
    return jsonify({'status': 'success', 'campaign_id': campaign_id})

#  PRODUCTS ENDPOINTS
@app.route('/api/search_product', methods=['POST'])
def search_product():
    data = request.json
    user_email = session.get('user_email', 'guest')
    product_name = data.get('product_name')
    category = data.get('category')
    
    # Track search in products table
    products_table.update_item(
        Key={'category': category},
        UpdateExpression="SET #searches = if_not_exists(#searches, :zero) + :inc",
        ExpressionAttributeNames={'#searches': 'searches'},
        ExpressionAttributeValues={':inc': 1, ':zero': 0}
    )
    
    send_sns_notification("Product Search", f"{user_email} searched: {product_name}")
    
    return jsonify({
        'success': True,
        'results': [f"{product_name} - ${100+len(product_name)}", f"{product_name} Premium - ${200+len(product_name)}"]
    })

@app.route('/api/click_product', methods=['POST'])
def click_product():
    data = request.json
    user_email = session.get('user_email', 'guest')
    
    send_sns_notification("Product Click", f"{user_email} clicked: {data['product_name']}")
    
    return jsonify({'success': True, 'message': 'Tracked!'})

if __name__ == '__main__':
    print("🚀 AWS Marketing Platform Starting...")
    print("📋 Required DynamoDB Tables: Users, Admin, Products, Campaigns")
    print("📱 SNS Topic ARN - Update SNS_TOPIC_ARN in code!")

    app.run(host='0.0.0.0', port=5000, debug=True)
