# Skin Product Live Consultation and Shopping with LLM

A comprehensive skincare e-commerce platform with integrated live dermatologist consultations powered by AI/LLM technology.

## Features

### 🛍️ E-Commerce Functionality
- Product browsing with advanced filtering (skin type, product type, brand)
- Shopping cart and checkout system
- Order management and tracking
- Product recommendations

### 👩‍⚕️ Live Consultation
- Real-time video consultations with dermatologists via Twilio
- Appointment booking system with availability management
- Integrated payment processing
- Consultation history tracking

### 🤖 AI-Powered Features
- LLM integration using GROQ API for intelligent product recommendations
- Natural language processing for customer queries
- Personalized skincare advice

### 🔐 User Management
- Secure user authentication with bcrypt password hashing
- Email verification and password reset functionality
- Separate customer and dermatologist portals

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: MySQL with SQLAlchemy ORM
- **Video**: Twilio Video API
- **AI/LLM**: GROQ API
- **Email**: Gmail SMTP + Mailtrap for testing
- **Authentication**: bcrypt, itsdangerous
- **Frontend**: HTML, CSS, JavaScript (Jinja2 templates)

## Prerequisites

- Python 3.8+
- MySQL Server
- Twilio Account (for video consultations)
- GROQ API Key (for LLM features)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/mamathasg/Skin-product-live-consultation-and-shopping-with-llm.git
   cd Skin-product-live-consultation-and-shopping-with-llm
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   - Copy `.env.example` to `.env`
   ```bash
   cp .env.example .env
   ```
   - Edit `.env` and fill in your credentials:
     - Database connection string
     - Twilio credentials (Account SID, API Key SID, API Key Secret)
     - GROQ API key
     - Email configuration (Gmail and Mailtrap)
     - Flask secret key

5. **Set up the database**
   - Create a MySQL database named `skincare_ecommerce`
   - Import the database schema (if provided) or run migrations

6. **Run the application**
   ```bash
   python app.py
   ```

7. **Access the application**
   - Open your browser and navigate to `http://localhost:5000`

## Environment Variables

See `.env.example` for all required environment variables. Key variables include:

- `DB_URL`: MySQL database connection string
- `TWILIO_ACCOUNT_SID`: Twilio account identifier
- `TWILIO_API_KEY_SID`: Twilio API key
- `TWILIO_API_KEY_SECRET`: Twilio API secret
- `GROQ_API_KEY`: GROQ LLM API key
- `SECRET_KEY`: Flask application secret key
- `GMAIL_ADDRESS`: Gmail address for sending emails
- `GMAIL_APP_PASSWORD`: Gmail app-specific password

## Project Structure

```
.
├── app.py                 # Main Flask application
├── config.py              # Configuration and database setup
├── llm_utils.py          # LLM utility functions
├── requirements.txt       # Python dependencies
├── static/               # Static files (CSS, JS, images)
├── templates/            # HTML templates
├── .env                  # Environment variables (not in git)
├── .env.example          # Environment variables template
└── .gitignore            # Git ignore rules
```

## Usage

### For Customers
1. Sign up for an account
2. Browse products and add to cart
3. Complete checkout process
4. Book consultations with dermatologists
5. Join live video sessions at scheduled times

### For Dermatologists
1. Log in to dermatologist portal
2. View scheduled appointments
3. Join consultation sessions
4. Provide skincare recommendations

## Security Notes

- Never commit the `.env` file to version control
- All passwords are hashed using bcrypt
- Use environment variables for all sensitive credentials
- Enable HTTPS in production
- Regularly update dependencies for security patches

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Support

For issues or questions, please open an issue on GitHub.
