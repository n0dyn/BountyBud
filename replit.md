# BountyBud - Security Testing Toolkit

## Overview

BountyBud is a comprehensive web-based toolkit designed for bug bounty hunters and security researchers. The application provides an intuitive interface for generating security testing commands, creating XSS payloads, and accessing curated security tools. Built with Flask and Bootstrap, it serves as a centralized hub for common security testing workflows, helping researchers save time and standardize their approach to vulnerability discovery.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: Bootstrap 5.3.2 with custom CSS for dark theme
- **JavaScript**: Vanilla JavaScript for interactive features including clipboard functionality and toast notifications
- **Template Engine**: Jinja2 templates with a base template structure for consistent navigation and styling
- **Responsive Design**: Mobile-first approach using Bootstrap's grid system

### Backend Architecture
- **Framework**: Flask web framework with Python
- **Route Structure**: Simple route-based architecture with separate endpoints for each major feature (tools, XSS payloads, security tools, documentation)
- **API Design**: RESTful API endpoint for command generation (`/api/generate-command`)
- **Session Management**: Flask sessions with configurable secret key from environment variables

### Data Storage Solutions
- **File-based Storage**: JSON files for static data including command templates and XSS payload definitions
- **Template Data**: Command templates stored in `static/data/command_templates.json` with structured tool definitions
- **Payload Database**: XSS payloads organized by context, encoding, and categories in `static/data/xss_payloads.json`

### Security Features
- **Cache Control**: HTTP headers configured to prevent caching issues in deployment
- **Environment Configuration**: Secret key sourced from environment variables with fallback
- **Input Validation**: Server-side validation for API endpoints

### Component Organization
- **Modular Templates**: Separate HTML templates for each major feature area
- **Static Asset Management**: Organized CSS, JavaScript, and image assets
- **Data Separation**: Business logic separated from presentation through JSON data files

## External Dependencies

### Frontend Dependencies
- **Bootstrap 5.3.2**: UI framework loaded via CDN for responsive design and components
- **Bootstrap Icons**: Icon library for consistent iconography throughout the application
- **CDN Strategy**: External resources loaded from CDNs for better performance and reliability

### Python Dependencies
- **Flask**: Core web framework for routing and request handling
- **Standard Library**: Uses built-in `json` and `os` modules for data handling and environment variable access

### Data Sources
- **Security Tool Information**: Curated collection of security tools with documentation links and usage guides
- **Command Templates**: Pre-defined command structures for popular security testing tools including Subfinder, HTTPx, Amass, and DNSGen
- **XSS Payload Database**: Comprehensive collection of XSS payloads categorized by injection context and encoding requirements

### Development Tools
- **Static File Serving**: Flask's built-in static file handling for CSS, JavaScript, and images
- **Template Rendering**: Jinja2 integration for dynamic content generation
- **JSON Processing**: Built-in JSON handling for configuration and data files