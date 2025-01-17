from flask import Flask, render_template, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import uuid
import re
import os
import os.path
from datetime import datetime, timedelta  # Import datetime module
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

class Expense:
    def __init__(self, material, quantity, price, total, date, random_id=None, spreadsheet_id=None, range_name=None):
        self.material = material
        self.quantity = quantity
        self.price = price
        self.total = total
        self.date = date
        self.random_id = random_id
        self.spreadsheet_id = spreadsheet_id
        self.range_name = range_name

    def __repr__(self):
        return f"<{self.material}, {self.quantity}, {self.price}, {self.total}, {self.date}, {self.random_id}>"

app = Flask(__name__)
app.secret_key = 'yZJPf2C6URJUvybJcZJwYb4rjwcJ6zwC'  # Set a secret key for session management
login_manager = LoginManager()
login_manager.init_app(app)
RENDER_DISK_PATH = '/mnt/render-disk'

SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

@app.route('/')
def main():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch the spreadsheet info associated with the current user
    if current_user.is_authenticated:
        username = current_user.id
        spreadsheet_id, range_name = get_spreadsheet_info(username)
        page = request.args.get('page', 1, type=int)
        
        expenses, total_expenses, total_amount, expenses_loaded = load_expenses(page)
        total_amount_all_pages = compute_total_amount_all_pages(load_expenses, total_expenses)

        # Fetch total income from Google Sheets API
        if spreadsheet_id and range_name:
            total_income_all_pages = get_total_income_of_all_pages(spreadsheet_id, range_name)
        else:
            total_income_all_pages = 0  # Set total income to 0 if no spreadsheet info found
        
        if total_income_all_pages != 0 or total_amount != 0:    
            total_combined = total_income_all_pages + total_amount
            if total_combined != 0:
                total_income_percentage = round((total_income_all_pages / total_combined) * 100)
                total_amount_percentage = round((total_amount / total_combined) * 100)
            else:
                total_income_percentage = 0
                total_amount_percentage = 0
        else:
            total_income_percentage = 0
            total_amount_percentage = 0
            
        
        return render_template('index-dashboard.html', total_income_all_pages=total_income_all_pages, total_amount=total_amount_all_pages, total_income_percentage=total_income_percentage, total_amount_percentage=total_amount_percentage, username=username)
    else:
        return redirect(url_for('login'))

# EXPENSES SECTION
users = {
    'user1': {
        'username': 'user1',
        'password': generate_password_hash('password1')  # Hashed password
    },
    'user2': {
        
        'username': 'user1',
        'password': generate_password_hash('password2')  # Hashed password
    }
}

# User class for Flask-Login
class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    user = User()
    user.id = user_id
    return user

from flask import render_template

@app.route('/expenses')
def expenses():
    if current_user.is_authenticated:
        page = request.args.get('page', 1, type=int)
        last_7_days = request.args.get('last_7_days', False, type=bool)
        last_28_days = request.args.get('last_28_days', False, type=bool)
        
        if last_7_days:
            expenses, total_expenses, total_amount, expenses_loaded = load_expenses_last_7_days(page)
            total_amount_all_pages = compute_total_amount_all_pages(load_expenses_last_7_days, total_expenses)
        elif last_28_days:
            expenses, total_expenses, total_amount, expenses_loaded = load_expenses_last_28_days(page)
            total_amount_all_pages = compute_total_amount_all_pages(load_expenses_last_28_days, total_expenses)
        else:
            expenses, total_expenses, total_amount, expenses_loaded = load_expenses(page)
            total_amount_all_pages = compute_total_amount_all_pages(load_expenses, total_expenses)
        
        return render_template('index.html', expenses=expenses, page=page, total_expenses=total_expenses, total_amount=total_amount_all_pages, expenses_loaded=expenses_loaded, last_7_days=last_7_days, last_28_days=last_28_days)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_user_info()
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username]['password'], password):
            # Authentication successful, login user and create session
            user = User()
            user.id = username
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            # Authentication failed, show error message
            return 'Invalid username or password!'
    # If GET request, render the login page
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate username and password length
        if not (6 <= len(username) <= 20):
            return 'Username must be 6 to 20 characters long!'
        if not (6 <= len(password) <= 20):
            return 'Password must be 6 to 20 characters long!'
        
        if username in users:
            return 'Username already exists!'
        else:
            users[username] = {'username': username, 'password': generate_password_hash(password)}
            
            # Append user information to the CSV file if it doesn't exist
            csv_path = os.path.join(RENDER_DISK_PATH, "users.csv")
            if not os.path.exists(csv_path):
                with open(csv_path, "w") as f:
                    f.write("Username,Password\n")
            # Write user information
            with open(csv_path, "a") as f:
                f.write(f"{username},{generate_password_hash(password)}\n")
            
            # Create a unique CSV file for the user
            user_csv_filename = f"{username}_expenses.csv"
            user_csv_path = os.path.join(RENDER_DISK_PATH, user_csv_filename)
            if not os.path.exists(user_csv_path):
                with open(user_csv_path, "w") as f:
                    # Write header to the CSV file
                    f.write("Material,Quantity,Price,Total,Date,Random_ID\n")
            
            # Redirect to login page after successful signup
            return redirect(url_for('login'))
    # If GET request, render the signup page
    return render_template('signup.html')

def load_user_info():
    user_info = {}
    csv_path = "/mnt/render-disk/users.csv"
    if os.path.exists(csv_path):
        with open(csv_path, "r") as f:
            lines = f.readlines()
            for line in lines:
                username, password_hash = line.strip().split(',')
                user_info[username] = {'username': username, 'password': password_hash}
    return user_info

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/submit', methods=['POST'])
def submit():
    expense_material = request.form['material']
    expense_quantity = int(request.form.get('quantity'))
    expense_price = float(request.form['price'])
    expense_date = request.form['date']  # Get date input from the form
    random_id = str(uuid.uuid4())
    expense_total = float(expense_quantity * expense_price)
    
    # Convert date string to datetime object
    expense_date = datetime.strptime(expense_date, '%Y-%m-%d')
    
    new_expense = Expense(material=expense_material, quantity=expense_quantity, price=expense_price,
                          total=expense_total, date=expense_date, random_id=random_id)
    
    save_expense(new_expense)
    
    # Check if last 7 days or last 28 days filter is active
    last_7_days = request.args.get('last_7_days', False, type=bool)
    last_28_days = request.args.get('last_28_days', False, type=bool)
    
    if last_7_days:
        return redirect('/expenses?last_7_days=True')
    elif last_28_days:
        return redirect('/expenses?last_28_days=True')
    else:
        return redirect('/expenses')

@app.route('/delete', methods=['POST'])
def delete():
    random_id_to_delete = request.form.get('random_id')
    delete_expense(random_id_to_delete)
    
    # Check if last 7 days or last 28 days filter is active
    last_7_days = request.args.get('last_7_days', False, type=bool)
    last_28_days = request.args.get('last_28_days', False, type=bool)
    
    if last_7_days:
        return redirect('/expenses?last_7_days=True')
    elif last_28_days:
        return redirect('/expenses?last_28_days=True')
    else:
        return redirect('/expenses')
    
def load_expenses(page):
    # Define constants
    expenses_per_page = 8  # Number of expenses to display per page

    # Calculate start and end indices of expenses for the given page
    start_index = (page - 1) * expenses_per_page
    end_index = start_index + expenses_per_page

    # Get the username of the current user
    username = current_user.id  # Assuming `current_user` is defined elsewhere

    # Construct the filename for the user's expenses CSV file
    user_csv_filename = f"{username}_expenses.csv"

    # Construct the full path to the user's expenses CSV file
    user_csv_path = os.path.join(RENDER_DISK_PATH, user_csv_filename)

    # Initialize variables to store expenses data
    expenses = []  # List to hold Expense objects
    total_expenses = 0  # Total number of expenses in the CSV file
    total_amount = 0  # Total amount spent on expenses
    expenses_loaded = 0  # Number of expenses loaded for the current page

    # Check if the user's CSV file exists
    if os.path.exists(user_csv_path):
        # If the file exists, open it for reading
        with open(user_csv_path, "r") as f:
            # Read all lines from the file, skipping the header
            lines = f.readlines()[1:]  # Skip header

            # Count total number of expenses in the CSV file
            total_expenses = len(lines)

            # Iterate over lines in the file corresponding to the current page's expenses
            for line in lines[start_index:end_index]:
                # Split each line into its components
                parts = line.strip().split(',')

                # Extract individual components from the split line
                material, quantity, price, total, date_str, ran = parts

                # Convert date string to a datetime object
                date = datetime.strptime(date_str, '%Y-%m-%d')

                # Update total amount spent on expenses
                total_amount += float(total)

                # Create an Expense object and add it to the expenses list
                expenses.append(Expense(material=material, quantity=int(quantity), price=float(price),
                                        total=float(total), date=date, random_id=ran))

                # Increment the count of expenses loaded
                expenses_loaded += 1
    
    # Return the loaded expenses, total number of expenses, total amount spent, and number of expenses loaded
    return expenses, total_expenses, total_amount, expenses_loaded

def load_expenses_last_7_days(page):
    username = current_user.id
    user_csv_filename = f"{username}_expenses.csv"
    user_csv_path = os.path.join(RENDER_DISK_PATH, user_csv_filename)
    
    expenses_per_page = 8
    start_index = (page - 1) * expenses_per_page
    end_index = start_index + expenses_per_page
    
    expenses = []
    total_expenses = 0
    total_amount = 0
    expenses_loaded = 0
    
    if os.path.exists(user_csv_path):
        with open(user_csv_path, "r") as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                parts = line.strip().split(',')
                material, quantity, price, total, date_str, ran = parts
                date = datetime.strptime(date_str, '%Y-%m-%d')  # Convert date string to datetime object
                # Check if expense date is within the last 7 days
                if (datetime.now() - date) <= timedelta(days=7):
                    total_expenses += 1
                    if total_expenses > start_index and total_expenses <= end_index:
                        total_amount += float(total)
                        expenses.append(Expense(material=material, quantity=int(quantity), price=float(price),
                                                total=float(total), date=date, random_id=ran))
                        expenses_loaded += 1
                    if total_expenses >= end_index:
                        break  # Stop once we've collected enough expenses for the current page
    return expenses, total_expenses, total_amount, expenses_loaded

def load_expenses_last_28_days(page):
    username = current_user.id
    user_csv_filename = f"{username}_expenses.csv"
    user_csv_path = os.path.join(RENDER_DISK_PATH, user_csv_filename)
    
    expenses_per_page = 8
    start_index = (page - 1) * expenses_per_page
    end_index = start_index + expenses_per_page
    
    expenses = []
    total_expenses = 0
    total_amount = 0
    expenses_loaded = 0
    
    if os.path.exists(user_csv_path):
        with open(user_csv_path, "r") as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                parts = line.strip().split(',')
                material, quantity, price, total, date_str, ran = parts
                date = datetime.strptime(date_str, '%Y-%m-%d')  # Convert date string to datetime object
                # Check if expense date is within the last 28 days
                if (datetime.now() - date) <= timedelta(days=28):
                    total_expenses += 1
                    if total_expenses > start_index and total_expenses <= end_index:
                        total_amount += float(total)
                        expenses.append(Expense(material=material, quantity=int(quantity), price=float(price),
                                                total=float(total), date=date, random_id=ran))
                        expenses_loaded += 1
                    if total_expenses >= end_index:
                        break  # Stop once we've collected enough expenses for the current page
    return expenses, total_expenses, total_amount, expenses_loaded

def compute_total_amount_all_pages(load_expenses_func, total_pages):
    total_amount_all_pages = 0
    
    for page in range(1, total_pages + 1):
        _, _, total_amount, _ = load_expenses_func(page)
        total_amount_all_pages += total_amount
    
    return total_amount_all_pages

def save_expense(expense):
    username = current_user.id
    user_csv_filename = f"{username}_expenses.csv"
    user_csv_path = os.path.join(RENDER_DISK_PATH, user_csv_filename)
    
    with open(user_csv_path, "a") as f:
        f.write(f"{expense.material},{expense.quantity},{expense.price},{expense.total},"
                f"{expense.date.strftime('%Y-%m-%d')},{expense.random_id}\n")

def delete_expense(random_id):
    username = current_user.id
    user_csv_filename = f"{username}_expenses.csv"
    user_csv_path = os.path.join(RENDER_DISK_PATH, user_csv_filename)
    
    with open(user_csv_path, "r") as f:
        lines = f.readlines()   
    with open(user_csv_path, "w") as f:
        for line in lines:
            if random_id not in line:
                f.write(line)


# INCOME SECTION

def get_spreadsheet_info(username):
    user_info_filename = f"{username}_spreadsheet.csv"
    user_info_path = os.path.join(RENDER_DISK_PATH, user_info_filename)

    try:
        with open(user_info_path, "r") as file:
            data = file.readline().strip().split(",")
            return data[0], data[1]
    except FileNotFoundError:
        return None, None

def save_spreadsheet_info(username, spreadsheet_id, range_name):
    user_info_filename = f"{username}_spreadsheet.csv"
    user_info_path = os.path.join(RENDER_DISK_PATH, user_info_filename)

    with open(user_info_path, "w") as f:
        f.write(f"{spreadsheet_id},{range_name}\n")

@app.route("/income", methods=['GET'])
def income():
    username = current_user.id
    spreadsheet_id = request.args.get('spreadsheet_id')
    range_name = request.args.get('range_name')
    page = request.args.get('page', 1, type=int)
    last_7_days = request.args.get('last_7_days', False, type=bool)
    last_28_days = request.args.get('last_28_days', False, type=bool)

    saved_spreadsheet_id, saved_range_name = get_spreadsheet_info(username)

    if not spreadsheet_id and not range_name:
        # If both spreadsheet_id and range_name are not provided in the request,
        # use the saved spreadsheet info
        spreadsheet_id = saved_spreadsheet_id
        range_name = saved_range_name

    if not spreadsheet_id or not range_name:
        # Handle the case where user doesn't provide both parameters
        total_income = 0
        return render_template("index-income.html", page=page, error="Please provide both spreadsheet ID and range name.")

    # If user provided new spreadsheet info, save it
    if spreadsheet_id != saved_spreadsheet_id or range_name != saved_range_name:
        save_spreadsheet_info(username, spreadsheet_id, range_name)

    if last_7_days:
        # Fetch data for the last 7 days
        values, rows_loaded, total_income, income = get_sheet_data_last_7_days(spreadsheet_id, range_name, page)
    elif last_28_days:
        # Fetch data for the last 28 days
        values, rows_loaded, total_income, income = get_sheet_data_last_28_days(spreadsheet_id, range_name, page)
    else:
        # Fetch all data
        values, rows_loaded, total_income, income = get_sheet_data(spreadsheet_id, range_name, page)

    total_income_all_pages = get_total_income_of_all_pages(spreadsheet_id, range_name)

    return render_template("index-income.html", values=values, rows_loaded=rows_loaded, income=income, total_income=total_income, total_income_all_pages=total_income_all_pages, page=page, last_7_days=last_7_days, last_28_days=last_28_days)


def get_sheet_data(spreadsheet_id, range_name, page):
    # Check if token.json exists and load credentials
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        
    # If credentials are missing or invalid, obtain new credentials
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        # Save updated credentials to token.json
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    # Build Google Sheets API service
    service = build("sheets", "v4", credentials=creds)

    # Calculate start and end indices for pagination
    start_index = (page - 1) * 8 + 1
    end_index = start_index + 8

    # Access the spreadsheet and retrieve data from the specified range
    sheet = service.spreadsheets()
    result = (
        sheet.values()
        .get(spreadsheetId=spreadsheet_id, range=range_name)
        .execute()
    )
    values = result.get("values", [])

    # Initialize variables for paginated values and rows loaded
    paginated_values = []
    rows_loaded = 0

    # If values exist, paginate and load rows
    if values:
        paginated_values.append(values[0])  # Append header row
        for row_index in range(start_index, min(end_index, len(values))):
            paginated_values.append(values[row_index])  # Append rows
            rows_loaded += 1
            
    # Calculate total income from paginated values
    total_income = 0
    if paginated_values:
        for row in paginated_values[1:]:
            try:
                total_income += float(row[4])  # Assuming income is in the 5th column (index 4)
            except (ValueError, IndexError):
                pass
    
    # Print number of rows loaded for debugging purposes
    print(rows_loaded)
    
    # Return paginated values, rows loaded, total income, and income (undefined in your original code)
    return paginated_values, rows_loaded, total_income, income

def get_sheet_data_last_7_days(spreadsheet_id, range_name, page):
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    service = build("sheets", "v4", credentials=creds)

    seven_days_ago = datetime.now() - timedelta(days=7)

    start_index = (page - 1) * 8 + 1
    end_index = start_index + 8

    sheet = service.spreadsheets()
    result = (
        sheet.values()
        .get(spreadsheetId=spreadsheet_id, range=range_name, dateTimeRenderOption='FORMATTED_STRING', majorDimension='ROWS')
        .execute()
    )
    values = result.get("values", [])

    filtered_values = []
    rows_loaded = 0  # Initialize rows_loaded variable to track the number of rows loaded

    if values:
        filtered_values.append(values[0])  # Include the header row
        for row in values[1:]:
            try:
                date_value = datetime.strptime(row[0], '%m/%d/%Y %H:%M:%S')
                if date_value >= seven_days_ago:
                    if start_index <= len(filtered_values) < end_index:
                        filtered_values.append(row)
                        rows_loaded += 1  # Increment rows_loaded for each row processed
                    elif len(filtered_values) >= end_index:
                        break
            except (ValueError, IndexError):
                pass
            
    total_income = 0
    if filtered_values:
        for row in filtered_values[1:]:  # Exclude the header row
            try:
                total_income += float(row[4])  # Assuming amount is in the 5th column
            except (ValueError, IndexError):
                pass
    
    return filtered_values, rows_loaded, total_income, income

def get_sheet_data_last_28_days(spreadsheet_id, range_name, page):
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    service = build("sheets", "v4", credentials=creds)

    twentyeight_days_ago = (datetime.now() - timedelta(days=28)).strftime('%Y-%m-%d')

    start_index = (page - 1) * 8 + 1
    end_index = start_index + 8

    sheet = service.spreadsheets()
    result = (
        sheet.values()
        .get(spreadsheetId=spreadsheet_id, range=range_name, dateTimeRenderOption='FORMATTED_STRING', majorDimension='ROWS')
        .execute()
    )
    values = result.get("values", [])

    filtered_values = []
    rows_loaded = 0  # Initialize rows_loaded variable to track the number of rows loaded

    if values:
        filtered_values.append(values[0])  # Include the header row
        for row in values[1:]:
            try:
                date_value = datetime.strptime(row[0], '%m/%d/%Y %H:%M:%S').strftime('%Y-%m-%d')
                if date_value >= twentyeight_days_ago:
                    if start_index <= len(filtered_values) < end_index:
                        filtered_values.append(row)
                        rows_loaded += 1  # Increment rows_loaded for each row processed
                    elif len(filtered_values) >= end_index:
                        break
            except (ValueError, IndexError):
                pass

    total_income = 0
    if filtered_values:
        for row in filtered_values[1:]:  # Exclude the header row
            try:
                total_income += float(row[4])  # Assuming amount is in the 5th column
            except (ValueError, IndexError):
                pass

    return filtered_values, rows_loaded, total_income, income


def get_total_income_of_all_pages(spreadsheet_id, range_name):
    total_income_all_pages = 0
    page = 1
    
    while True:
        paginated_values, rows_loaded, total_income, _ = get_sheet_data(spreadsheet_id, range_name, page)
        if rows_loaded == 0:
            break
        total_income_all_pages += total_income
        page += 1

    return total_income_all_pages

@app.route("/help")
def help():
    return render_template('index-help.html')

if __name__ == "__main__":
    app.run(debug=True)