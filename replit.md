# BountyBud - Security Testing Toolkit

## Overview

BountyBud is a comprehensive web-based toolkit designed for bug bounty hunters and security researchers. The application provides command generation capabilities for security testing tools, XSS payload generation, curated security tool documentation, and educational resources. It serves as a centralized platform to streamline security testing workflows by automating command generation and providing quick access to essential security tools and techniques.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templates with Bootstrap 5 for responsive UI
- **CSS Framework**: Bootstrap 5 with custom dark theme styling
- **JavaScript**: Vanilla JavaScript for client-side interactions including clipboard functionality and dynamic content filtering
- **Theme**: Dark mode interface optimized for security professionals

### Backend Architecture
- **Web Framework**: Flask (Python) with minimal dependencies
- **Application Structure**: Route-based architecture with separate endpoints for each major feature
- **Session Management**: Flask sessions with configurable secret key via environment variables
- **API Design**: RESTful JSON API for command generation with POST endpoints

### Data Storage Solutions
- **Static Data**: JSON files for command templates and XSS payload definitions
- **File Structure**: Template-based data storage in `/static/data/` directory
- **No Database**: Application uses file-based storage for simplicity and portability

### Authentication and Authorization
- **Current State**: No authentication system implemented
- **Session Security**: Basic Flask session configuration with environment-based secret key
- **Access Control**: Open access to all features without user management

### Key Features Implementation
- **Command Generation**: Template-based system using JSON configuration files
- **XSS Payload Generator**: Context-aware payload generation with encoding options
- **Tool Documentation**: Static content management for security tool guides
- **Responsive Design**: Mobile-friendly interface with collapsible navigation

### Design Patterns
- **MVC Pattern**: Clear separation between routes (controllers), templates (views), and data (models)
- **Template Inheritance**: Base template system for consistent UI across all pages
- **Configuration Management**: Environment variable support for deployment flexibility
- **Static Asset Organization**: Structured CSS, JS, and data file organization

## External Dependencies

### Frontend Dependencies
- **Bootstrap 5.3.2**: UI framework and components via CDN
- **Bootstrap Icons 1.11.1**: Icon library for consistent iconography
- **External Assets**: Logo and images hosted on external domain (bb.nxit.cc)

### Backend Dependencies
- **Flask**: Core web framework for Python
- **Standard Library**: JSON, OS modules for file handling and environment variables

### Development Tools
- **Template System**: Jinja2 (included with Flask)
- **Static File Serving**: Flask's built-in static file handler
- **Session Management**: Flask's built-in session handling

### Data Sources
- **Command Templates**: Local JSON files defining tool commands and parameters
- **XSS Payloads**: Local JSON files containing payload definitions and contexts
- **Documentation**: Static HTML templates with embedded content

### External Integrations
- **CDN Resources**: Bootstrap and Bootstrap Icons via CDN for performance
- **Image Hosting**: External image hosting for branding assets
- **No Third-Party APIs**: Application operates independently without external API dependencies