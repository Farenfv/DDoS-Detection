# Contributing to DDoS Detection System

We welcome contributions to make this project even better! This guide will help you get started.

## 🚀 Quick Start for Contributors

### Development Environment Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/ddos-detection-system.git
cd ddos-detection-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .[dev]  # Install in development mode

# Install pre-commit hooks
pre-commit install
```

## 📋 Development Guidelines

### Code Style

We use strict code formatting and linting:

- **Black** for code formatting
- **Flake8** for linting
- **MyPy** for type checking
- **Bandit** for security analysis

```bash
# Format code
black .

# Run linting
flake8 src/ ddos_detection.py config.py

# Type checking
mypy src/ ddos_detection.py config.py

# Security check
bandit -r src/ ddos_detection.py
```

### Testing

All contributions must include appropriate tests:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov=ddos_detection --cov=config

# Run specific test file
pytest tests/test_detector.py

# Run with verbose output
pytest -v
```

### Documentation

- All functions must have comprehensive docstrings
- Use Google-style docstrings
- Update README.md for new features
- Add inline comments for complex logic

Example docstring:
```python
def detect_anomaly(self, ip: str, features: TrafficFeatures) -> DetectionResult:
    """
    Detect if traffic features indicate a DDoS attack.
    
    Args:
        ip: Source IP address
        features: Extracted traffic features
        
    Returns:
        DetectionResult with analysis results
        
    Raises:
        ValidationError: If input data is invalid
    """
```

## 🔄 Contribution Workflow

### 1. Create an Issue

Before starting work, create an issue describing:
- The problem you're solving
- Your proposed solution
- Any breaking changes

### 2. Fork and Branch

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

### 3. Make Changes

- Write clean, well-documented code
- Follow existing code patterns
- Add tests for new functionality
- Update documentation as needed

### 4. Test Your Changes

```bash
# Run full test suite
pytest

# Test the application manually
python ddos_detection.py

# Check code quality
pre-commit run --all-files
```

### 5. Commit and Push

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add advanced threat classification

- Implement 4-level threat assessment
- Add confidence scoring
- Update dashboard display
- Add unit tests for new functionality"

# Push to your fork
git push origin feature/your-feature-name
```

### 6. Create Pull Request

- Use the PR template
- Describe your changes clearly
- Link related issues
- Add screenshots for UI changes

## 🎯 Areas for Contribution

### High Priority
- **Performance Optimization**: Improve packet processing speed
- **ML Model Enhancement**: Better anomaly detection algorithms
- **Security Hardening**: Additional security measures
- **Documentation**: API documentation, tutorials

### Medium Priority
- **Database Integration**: Persistent storage for historical data
- **Alert System**: Email/SMS notifications
- **API Extensions**: Additional REST endpoints
- **Mobile Interface**: Responsive design improvements

### Low Priority
- **Plugins System**: Extensible architecture
- **Multi-language Support**: Internationalization
- **Advanced Visualizations**: More chart types
- **Integration Examples**: Docker, Kubernetes configs

## 🐛 Bug Reports

When reporting bugs, include:

```markdown
## Bug Description
Brief description of the issue

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: Windows 10 / Ubuntu 20.04 / macOS 12
- Python version: 3.9.7
- Package versions: (from pip freeze)

## Logs
```
Relevant log entries
```

## Additional Context
Screenshots, error messages, etc.
```

## 💡 Feature Requests

For new features, provide:
- **Use case**: Why is this needed?
- **Proposed solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Implementation notes**: Technical considerations

## 📝 Commit Message Guidelines

Use conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(detector): add burst detection algorithm
fix(monitor): resolve packet capture memory leak
docs(readme): update installation instructions
```

## 🔒 Security

For security vulnerabilities:
1. **DO NOT** create public issues
2. Email maintainers directly
3. Provide detailed reproduction steps
4. Allow time for fix before disclosure

## 📞 Getting Help

- **GitHub Discussions**: General questions
- **Issues**: Bug reports and feature requests
- **Email**: Direct contact for sensitive matters

## 🏆 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Given appropriate GitHub badges

Thank you for contributing to the DDoS Detection System! 🛡️
