# Contributing to Honey Claw

Thanks for your interest in contributing to Honey Claw! 🍯

## Quick Start

```bash
# Clone the repo
git clone https://github.com/openclaw/honeyclaw.git
cd honeyclaw

# Test a template locally
cd templates/basic-ssh
docker build -t honeyclaw/basic-ssh:dev .
docker run -p 2222:22 honeyclaw/basic-ssh:dev
```

## Development Setup

1. **Docker** - Required for testing templates
2. **Python 3.10+** - For service simulators
3. **Node.js 18+** - For fake-api template

## Adding a New Template

1. Create directory: `templates/<your-template>/`
2. Add required files:
   - `config.yaml` - Template configuration
   - `Dockerfile` - Container definition
   - Service-specific configs
3. Update `README.md` with new template
4. Add tests in `tests/`

## Code Style

- Shell: Follow [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
- Python: Black + isort
- JavaScript: Prettier

## Testing

```bash
# Run all tests
./scripts/test.sh

# Test specific template
./scripts/test.sh basic-ssh
```

## Pull Request Process

1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing-honeypot`)
3. Make changes
4. Test locally
5. Submit PR

## Security

Found a vulnerability? Please report privately to security@openclaw.dev

Do NOT create public issues for security problems.
