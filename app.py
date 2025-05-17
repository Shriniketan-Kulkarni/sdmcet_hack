from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from bs4 import BeautifulSoup
import pandas as pd
import re
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import tldextract
import os
from datetime import datetime
import urllib.parse
import random
import email_validator
from email_validator import validate_email, EmailNotValidError
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from werkzeug.utils import secure_filename
import csv

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Change this to a secure secret key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_valid_email(email):
    try:
        # Validate email format
        validation = validate_email(email, check_deliverability=False)
        # Get normalized email
        normalized_email = validation.normalized
        return normalized_email
    except EmailNotValidError:
        return None

def get_search_queries(country, city, industry, keyword):
    # Generate multiple search query variations
    queries = [
        f"{industry} {keyword} {city} {country}",
        f"{industry} store {city} {country}",
        f"{keyword} {industry} {city} {country}",
        f"buy {industry} {keyword} {city} {country}",
        f"{industry} shop {city} {country}",
        f"{keyword} store {city} {country}",
        f"{industry} {city} {country}",
        f"{keyword} {city} {country}"
    ]
    return queries

def get_websites_from_google(country, city, industry, keyword, count, filters):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")  # Disable GPU hardware acceleration
    chrome_options.add_argument("--disable-software-rasterizer")  # Disable software rasterizer
    chrome_options.add_argument("--disable-extensions")  # Disable extensions
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--disable-notifications")  # Disable notifications
    chrome_options.add_argument("--disable-popup-blocking")  # Disable popup blocking
    chrome_options.add_argument("--disable-infobars")  # Disable infobars
    chrome_options.add_argument("--disable-logging")  # Disable logging
    chrome_options.add_argument("--log-level=3")  # Set log level to fatal
    chrome_options.add_argument("--silent")  # Run in silent mode
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
    
    driver = None
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
        all_websites = set()
        
        queries = get_search_queries(country, city, industry, keyword)
        
        for query in queries:
            try:
                search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}&num={count}"
                print(f"Searching with query: {query}")
                
                driver.get(search_url)
                time.sleep(3)
                
                soup = BeautifulSoup(driver.page_source, 'html.parser')
                
                search_results = (
                    soup.find_all('div', class_='g') or
                    soup.find_all('div', class_='yuRUbf') or
                    soup.find_all('div', {'class': ['g', 'yuRUbf']}) or
                    soup.find_all('div', class_='tF2Cxc') or
                    soup.find_all('div', class_='rc')
                )
                
                for result in search_results:
                    link = result.find('a')
                    if link and 'href' in link.attrs:
                        url = link['href']
                        if url.startswith('http'):
                            all_websites.add(url)
                
                if len(all_websites) >= count:
                    break
                    
            except Exception as e:
                print(f"Error with query '{query}': {str(e)}")
                continue
        
        websites = list(all_websites)[:count]
        print(f"Found {len(websites)} websites")
        return websites
        
    except Exception as e:
        print(f"Error during Google search: {str(e)}")
        return []
    finally:
        if driver:
            try:
                driver.quit()
            except Exception as e:
                print(f"Error closing Chrome driver: {str(e)}")

def check_website_status(url, filters):
    try:
        start_time = time.time()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        # Increase timeout to 15 seconds
        response = requests.get(url, timeout=15, headers=headers, verify=False)
        load_time = time.time() - start_time
        
        # Check load time filter
        if filters.get('load_time') and load_time > 5:  # Reduced threshold to 5 seconds
            return None, None, "Slow loading"
        
        # Check active status filter
        if filters.get('active_only') and response.status_code != 200:
            return None, None, "Inactive"
        
        # Check Shopify filter
        is_shopify = 'shopify' in response.text.lower() or 'myshopify.com' in url
        if filters.get('shopify_only') and not is_shopify:
            return None, None, "Not Shopify"
        
        # Check if website has contact information
        if filters.get('has_contact'):
            has_email = bool(re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text))
            has_phone = bool(re.search(r'(?:whatsapp|tel|phone|mobile|call|contact)[\s:]*[+]?(?:\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', response.text.lower()))
            if not (has_email or has_phone):
                return None, None, "No Contact Info"
        
        # If all filters pass, return the content
        return response.text, load_time, "Active"
    except requests.exceptions.Timeout:
        print(f"Timeout checking website {url}")
        return None, None, "Timeout"
    except requests.exceptions.RequestException as e:
        print(f"Error checking website {url}: {str(e)}")
        return None, None, "Error"
    except Exception as e:
        print(f"Unexpected error checking website {url}: {str(e)}")
        return None, None, "Error"

def extract_phone_number(text):
    # Common phone number patterns
    patterns = [
        r'(?:whatsapp|tel|phone|mobile|call|contact)[\s:]*[+]?(?:\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',  # With labels
        r'(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',  # Standard format
        r'(?:\+\d{1,3}[-.\s]?)?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}',        # Without parentheses
        r'(?:\+\d{1,3}[-.\s]?)?\d{4}[-.\s]?\d{3}[-.\s]?\d{3}',        # Alternative format
        r'(?:\+\d{1,3}[-.\s]?)?\d{10}',                               # Plain 10 digits
        r'(?:\+\d{1,3}[-.\s]?)?\d{3}[-.\s]?\d{7}',                    # 3-7 format
        r'(?:\+\d{1,3}[-.\s]?)?\d{5}[-.\s]?\d{5}',                    # 5-5 format
        r'(?:\+\d{1,3}[-.\s]?)?\d{4}[-.\s]?\d{6}',                    # 4-6 format
        r'(?:\+\d{1,3}[-.\s]?)?\d{2}[-.\s]?\d{8}'                     # 2-8 format
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text.lower())
        if matches:
            # Clean and format the phone number
            phone = matches[0]
            # Remove all non-digit characters except +
            phone = re.sub(r'[^\d+]', '', phone)
            # Ensure proper formatting
            if phone.startswith('+'):
                return phone
            elif len(phone) == 10:
                return f"+91{phone}"  # Assuming Indian numbers, adjust country code as needed
            elif len(phone) > 10:
                return f"+{phone}"
            return phone
    return None

def get_contact_page_url(url):
    try:
        # Common contact page patterns
        contact_patterns = [
            '/contact',
            '/contact-us',
            '/contactus',
            '/contact.html',
            '/contact-us.html',
            '/contactus.html',
            '/about/contact',
            '/about-us/contact',
            '/about/contact-us',
            '/about-us/contact-us',
            '/support/contact',
            '/help/contact',
            '/reach-us',
            '/get-in-touch',
            '/connect-with-us'
        ]
        
        # Try to find contact page link
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(url, headers=headers, verify=False, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for contact page links
        contact_links = soup.find_all('a', href=True)
        for link in contact_links:
            href = link['href'].lower()
            if any(pattern in href for pattern in contact_patterns):
                # Handle relative URLs
                if href.startswith('/'):
                    base_url = '/'.join(url.split('/')[:3])  # Get domain
                    return base_url + href
                elif href.startswith('http'):
                    return href
                else:
                    return url.rstrip('/') + '/' + href.lstrip('/')
        
        return None
    except Exception as e:
        print(f"Error finding contact page: {str(e)}")
        return None

def extract_contact_info(html_content, url):
    if not html_content:
        return []
    
    soup = BeautifulSoup(html_content, 'html.parser')
    contact_info = {'url': url, 'emails': None, 'phone': None, 'contact_type': None}
    
    # First, try to find support email directly
    support_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html_content)
    for email in support_emails:
        if any(term in email.lower() for term in ['support', 'care', 'help', 'contact', 'info']):
            normalized_email = is_valid_email(email)
            if normalized_email:
                contact_info['emails'] = normalized_email
                contact_info['contact_type'] = 'support'
                break
    
    # Look for phone numbers in the entire HTML content first
    phone_number = extract_phone_number(html_content)
    if phone_number:
        contact_info['phone'] = phone_number
        if not contact_info['contact_type']:
            contact_info['contact_type'] = 'html'
    
    # If no support email found, continue with regular extraction
    if not contact_info['emails'] or not contact_info['phone']:
        # Define priority order for contact locations
        contact_locations = [
            # Priority 1: Contact page links
            ('contact_page', soup.find_all('a', href=re.compile(r'contact|about|reach|connect|support|help', re.I))),
            # Priority 2: Contact sections
            ('contact_section', soup.find_all(['div', 'section'], class_=re.compile(r'contact|email|footer|phone|tel|whatsapp|care|support|connect|reach|help', re.I))),
            # Priority 3: Footer
            ('footer', soup.find_all('footer')),
            # Priority 4: Contact meta tags
            ('meta', soup.find_all('meta', {'name': re.compile(r'contact|phone|tel|whatsapp|email|care|support|connect|reach|help', re.I)})),
            # Priority 5: Contact page content
            ('contact_content', soup.find_all(['div', 'section'], id=re.compile(r'contact|email|footer|phone|tel|whatsapp|care|support|connect|reach|help', re.I))),
            # Priority 6: Script tags
            ('script', soup.find_all('script', string=re.compile(r'@|phone|tel|whatsapp|email|care|support|connect|reach|help'))),
            # Priority 7: Entire page
            ('all', [soup])
        ]
        
        # Try each location in priority order
        for contact_type, elements in contact_locations:
            for element in elements:
                # Skip if we already have both email and phone
                if contact_info['emails'] and contact_info['phone']:
                    return [contact_info]
                
                if contact_type == 'mailto':
                    # Extract email from mailto links
                    href = element.get('href', '')
                    email = href.replace('mailto:', '').strip()
                    if email and not contact_info['emails']:
                        normalized_email = is_valid_email(email)
                        if normalized_email:
                            contact_info['emails'] = normalized_email
                            contact_info['contact_type'] = contact_type
                else:
                    # Extract from text content
                    text = element.get_text()
                    
                    # Extract email if not found yet
                    if not contact_info['emails']:
                        # Look for labeled emails first
                        email_labels = [
                            'e-mail:', 'email:', 'mail:', 'contact:', 'care:', 'support:',
                            'e-mail', 'email', 'mail', 'contact', 'care', 'support',
                            'write to us:', 'write to us', 'reach us:', 'reach us',
                            'connect with us:', 'connect with us', 'get in touch:', 'get in touch',
                            'customer care:', 'customer care', 'customer support:', 'customer support',
                            'for any queries:', 'for any queries', 'for queries:', 'for queries',
                            'for support:', 'for support', 'for assistance:', 'for assistance',
                            'help:', 'help', 'technical support:', 'technical support',
                            'customer service:', 'customer service', 'contact us:', 'contact us',
                            'customercare', 'customer care', 'customer support', 'support'
                        ]
                        
                        # First try to find emails with labels
                        for label in email_labels:
                            if label in text.lower():
                                # Extract text after the label
                                parts = text.lower().split(label, 1)
                                if len(parts) > 1:
                                    # Find the first email in the text after the label
                                    potential_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', parts[1])
                                    if potential_emails:
                                        normalized_email = is_valid_email(potential_emails[0])
                                        if normalized_email:
                                            contact_info['emails'] = normalized_email
                                            contact_info['contact_type'] = contact_type
                                            break
                        
                        # If no labeled email found, try general email extraction with prioritization
                        if not contact_info['emails']:
                            # First try to find emails in contact-related sections
                            contact_section = element.find_parent(['div', 'section'], class_=re.compile(r'contact|email|footer|phone|tel|whatsapp|care|support|connect|reach|help', re.I))
                            if contact_section:
                                potential_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', contact_section.get_text())
                            else:
                                potential_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
                            
                            # First try to find emails with contact-related terms
                            contact_terms = ['contact', 'info', 'support', 'help', 'sales', 'team', 'care', 'service', 'connect', 'reach', 'query', 'assist', 'technical', 'customercare']
                            
                            # Prioritize support emails
                            support_emails = [email for email in potential_emails if any(term in email.lower() for term in contact_terms)]
                            if support_emails:
                                for email in support_emails:
                                    normalized_email = is_valid_email(email)
                                    if normalized_email:
                                        contact_info['emails'] = normalized_email
                                        contact_info['contact_type'] = contact_type
                                        break
                            
                            # If no support email found, try other contact terms
                            if not contact_info['emails']:
                                for email in potential_emails:
                                    # Skip common non-contact emails
                                    if any(skip in email.lower() for skip in ['noreply', 'no-reply', 'donotreply', 'do-not-reply', 'spam', 'bot', 'test', 'example', 'demo']):
                                        continue
                                    
                                    # Check if email contains any contact-related terms
                                    if any(term in email.lower() for term in contact_terms):
                                        normalized_email = is_valid_email(email)
                                        if normalized_email:
                                            contact_info['emails'] = normalized_email
                                            contact_info['contact_type'] = contact_type
                                            break
                            
                            # If no prioritized email found, take the first valid email
                            if not contact_info['emails']:
                                for email in potential_emails:
                                    # Skip non-contact emails
                                    if any(skip in email.lower() for skip in ['noreply', 'no-reply', 'donotreply', 'do-not-reply', 'spam', 'bot', 'test', 'example', 'demo']):
                                        continue
                                    
                                    normalized_email = is_valid_email(email)
                                    if normalized_email:
                                        contact_info['emails'] = normalized_email
                                        contact_info['contact_type'] = contact_type
                                        break
                    
                    # Extract phone if not found yet
                    if not contact_info['phone']:
                        phone = extract_phone_number(text)
                        if phone:
                            contact_info['phone'] = phone
                            if not contact_info['contact_type']:
                                contact_info['contact_type'] = contact_type
    
    # Only return if we found at least one contact method
    if contact_info['emails'] or contact_info['phone']:
        return [contact_info]
    return []

def process_website(website_data):
    url = website_data['url']
    filters = website_data['filters']
    
    try:
        # First try to get contact page
        contact_page_url = get_contact_page_url(url)
        contact_info = None
        
        if contact_page_url:
            contact_html, _, _ = check_website_status(contact_page_url, {})
            if contact_html:
                contact_info = extract_contact_info(contact_html, url)
        
        # If no contact page or no contact info found, try main page
        if not contact_info:
            html_content, _, _ = check_website_status(url, {})
            if html_content:
                contact_info = extract_contact_info(html_content, url)
        
        return contact_info[0] if contact_info else None
    except Exception as e:
        print(f"Error processing website {url}: {str(e)}")
        return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Validate input
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Please check your login details and try again.', 'error')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

CSV_FOLDER = os.path.join(os.getcwd(), 'csvs')
os.makedirs(CSV_FOLDER, exist_ok=True)

@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    if 'csv_file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('index'))
    file = request.files['csv_file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('index'))
    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(CSV_FOLDER, filename)
        file.save(filepath)
        # Read URLs from CSV
        urls = []
        with open(filepath, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row:
                    urls.append(row[0])
        # Process websites in parallel
        filters = {'shopify_only': False, 'active_only': False, 'load_time': False, 'has_contact': False}
        website_results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_url = {
                executor.submit(check_website_status, url, filters): url
                for url in urls
            }
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    html_content, load_time, status = future.result()
                    if html_content:
                        website_results.append({
                            'url': url,
                            'load_time': f"{load_time:.2f}s" if load_time else 'N/A',
                            'is_shopify': 'Yes' if 'shopify' in html_content.lower() else 'No',
                            'status': status
                        })
                except Exception as e:
                    print(f"Error processing {url}: {str(e)}")
        # Save websites to CSV
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        websites_csv = os.path.join('csvs', f'websites_{timestamp}.csv')
        websites_df = pd.DataFrame(website_results)
        websites_df.to_csv(websites_csv, index=False)
        # Step 2: Extract contact information
        contact_results = []
        website_data_list = [{'url': website['url'], 'filters': filters} for website in website_results]
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_website = {
                executor.submit(process_website, website_data): website_data
                for website_data in website_data_list
            }
            for future in as_completed(future_to_website):
                website_data = future_to_website[future]
                try:
                    contact_info = future.result()
                    if contact_info:
                        contact_results.append(contact_info)
                except Exception as e:
                    print(f"Error extracting contact info for {website_data['url']}: {str(e)}")
        contacts_csv = os.path.join('csvs', f'contacts_{timestamp}.csv')
        contacts_df = pd.DataFrame(contact_results)
        contacts_df.to_csv(contacts_csv, index=False)
        return render_template('results.html', 
                             websites=website_results,
                             contacts=contact_results,
                             websites_csv=websites_csv,
                             contacts_csv=contacts_csv)
    else:
        flash('Invalid file type. Please upload a CSV file.', 'error')
        return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        # Get form data
        country = request.form.get('country')
        city = request.form.get('city')
        industry = request.form.get('industry')
        keyword = request.form.get('keyword')
        count = int(request.form.get('count', 20))
        
        # Get filter settings - check if checkboxes are checked
        filters = {
            'shopify_only': request.form.get('shopify_only') == 'true',
            'active_only': request.form.get('active_only') == 'true',
            'load_time': request.form.get('load_time') == 'true',
            'has_contact': request.form.get('has_contact') == 'true'
        }
        
        print("Applied filters:", filters)  # Debug print
        
        # Step 1: Get websites
        websites = get_websites_from_google(country, city, industry, keyword, count, filters)
        
        # Process websites in parallel with reduced workers
        website_results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_url = {
                executor.submit(check_website_status, url, filters): url 
                for url in websites
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    html_content, load_time, status = future.result()
                    if html_content:  # Only add if we got content (filters passed)
                        website_results.append({
                            'url': url,
                            'load_time': f"{load_time:.2f}s",
                            'is_shopify': 'Yes' if 'shopify' in html_content.lower() else 'No',
                            'status': status
                        })
                except Exception as e:
                    print(f"Error processing {url}: {str(e)}")
        
        # If no results after filtering, try again with fewer filters
        if not website_results and any(filters.values()):
            print("No results with filters, trying without filters...")  # Debug print
            filters = {k: False for k in filters}  # Reset all filters
            website_results = []
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_url = {
                    executor.submit(check_website_status, url, filters): url 
                    for url in websites
                }
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        html_content, load_time, status = future.result()
                        if html_content:
                            website_results.append({
                                'url': url,
                                'load_time': f"{load_time:.2f}s",
                                'is_shopify': 'Yes' if 'shopify' in html_content.lower() else 'No',
                                'status': status
                            })
                    except Exception as e:
                        print(f"Error processing {url}: {str(e)}")
        
        # Save websites to CSV
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        websites_csv = os.path.join('csvs', f'websites_{timestamp}.csv')
        websites_df = pd.DataFrame(website_results)
        websites_df.to_csv(websites_csv, index=False)
        
        # Step 2: Extract contact information in parallel with reduced workers
        contact_results = []
        website_data_list = [{'url': website['url'], 'filters': filters} for website in website_results]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_website = {
                executor.submit(process_website, website_data): website_data 
                for website_data in website_data_list
            }
            
            for future in as_completed(future_to_website):
                website_data = future_to_website[future]
                try:
                    contact_info = future.result()
                    if contact_info:
                        contact_results.append(contact_info)
                except Exception as e:
                    print(f"Error extracting contact info for {website_data['url']}: {str(e)}")
        
        # Save contacts to CSV
        contacts_csv = os.path.join('csvs', f'contacts_{timestamp}.csv')
        contacts_df = pd.DataFrame(contact_results)
        contacts_df.to_csv(contacts_csv, index=False)
        
        return render_template('results.html', 
                             websites=website_results,
                             contacts=contact_results,
                             websites_csv=websites_csv,
                             contacts_csv=contacts_csv)
    
    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join('csvs', filename), as_attachment=True)

def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

if __name__ == '__main__':
    # Initialize the database
    init_db()
    
    # Disable SSL verification warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Configure Flask for better stability
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    
    # Run Flask with threaded mode and proper error handling
    try:
        app.run(debug=True, threaded=True, use_reloader=True)
    except Exception as e:
        print(f"Error starting Flask server: {str(e)}")
        # Attempt to clean up any remaining Chrome processes
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if 'chrome' in proc.info['name'].lower():
                    proc.kill()
        except:
            pass 
