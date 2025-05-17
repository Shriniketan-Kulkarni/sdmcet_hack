# Website Contact Scraper

A Flask web application that scrapes contact information from websites based on specified criteria.

## Features

- Search websites by country, state, industry, and keywords
- Filter for Shopify websites
- Check website load time (filters out slow-loading sites)
- Extract email addresses from websites
- Export results to CSV

## Requirements

- Python 3.7+
- Chrome browser (for Selenium)
- ChromeDriver (automatically installed by webdriver-manager)

## Installation

1. Clone this repository
2. Create a virtual environment:
   ```
   python -m venv venv
   ```
3. Activate the virtual environment:
   - Windows:
     ```
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```
     source venv/bin/activate
     ```
4. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Start the Flask application:
   ```
   python app.py
   ```
2. Open your web browser and navigate to `http://localhost:5000`
3. Enter your search criteria:
   - Country
   - State
   - Industry
   - Keywords
4. Click "Search" to start the scraping process
5. View the results and download the CSV file

## Notes

- The application will only process websites that load within 5 seconds
- Only Shopify websites will be included in the results
- Email addresses are extracted from the visible text of the websites
- Results are automatically saved to a CSV file

## Disclaimer

Please ensure you have permission to scrape the websites and comply with their terms of service and robots.txt files. This tool is for educational purposes only. 