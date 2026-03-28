#!/usr/bin/env node

/**
 * Development Server Launcher
 * Automatically starts all services for Zein Security WAF
 */

const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

function log(service, message, color = 'reset') {
  const timestamp = new Date().toLocaleTimeString();
  console.log(`${colors[color]}[${timestamp}] [${service}]${colors.reset} ${message}`);
}

function checkCommand(command) {
  return new Promise((resolve) => {
    const isWindows = process.platform === 'win32';
    const checkCmd = isWindows ? `where ${command}` : `which ${command}`;
    exec(checkCmd, (error) => {
      resolve(!error);
    });
  });
}

function checkDocker() {
  return new Promise((resolve) => {
    exec('docker --version', (error) => {
      if (error) {
        log('SYSTEM', 'Docker not found. Services will run locally if available.', 'yellow');
        resolve(false);
      } else {
        log('SYSTEM', 'Docker detected. Using Docker for database and Redis.', 'green');
        resolve(true);
      }
    });
  });
}

function startDockerServices() {
  return new Promise((resolve) => {
    log('DOCKER', 'Starting PostgreSQL and Redis...', 'blue');
    const docker = spawn('docker-compose', ['up', '-d', 'postgres', 'redis'], {
      cwd: path.join(__dirname, '..'),
      stdio: 'inherit',
      shell: true
    });

    docker.on('error', (error) => {
      log('DOCKER', 'Docker error: ' + error.message, 'red');
      log('DOCKER', 'Please ensure Docker Desktop is running!', 'yellow');
      log('DOCKER', '1. Open Docker Desktop application', 'yellow');
      log('DOCKER', '2. Wait for it to show "Running" status', 'yellow');
      log('DOCKER', '3. Then run: npm run dev again', 'yellow');
      setTimeout(() => resolve(), 2000);
    });

    docker.on('close', (code) => {
      if (code === 0) {
        log('DOCKER', 'Database services started successfully!', 'green');
        log('DOCKER', 'Waiting for database to be ready (15 seconds)...', 'yellow');
        // Wait longer for database to be fully ready
        setTimeout(() => {
          // Test database connection
          exec('docker exec zein-postgres psql -U zein_waf -d zein_security -c "SELECT 1;"', (error) => {
            if (error) {
              log('DOCKER', 'Database not ready yet, waiting 10 more seconds...', 'yellow');
              setTimeout(() => resolve(), 10000);
            } else {
              log('DOCKER', 'Database is ready!', 'green');
              // Set password to ensure it's correct
              exec('docker exec zein-postgres psql -U zein_waf -d zein_security -c "ALTER USER zein_waf WITH PASSWORD \'popyalena07\';"', () => {
                resolve();
              });
            }
          });
        }, 15000);
      } else {
        log('DOCKER', 'Docker services may already be running or Docker is not available.', 'yellow');
        log('DOCKER', 'If you see connection errors, ensure Docker Desktop is running!', 'yellow');
        // Still try to set password if containers are running
        exec('docker exec zein-postgres psql -U zein_waf -d zein_security -c "ALTER USER zein_waf WITH PASSWORD \'popyalena07\';"', () => {
          setTimeout(() => resolve(), 2000);
        });
      }
    });
  });
}

function startService(name, command, args, cwd, color) {
  return new Promise((resolve) => {
    log(name, `Starting ${name}...`, color);
    
    const service = spawn(command, args, {
      cwd: cwd || path.join(__dirname, '..'),
      stdio: 'inherit',
      shell: true,
      env: { ...process.env }
    });

    service.on('error', (error) => {
      log(name, `Error starting ${name}: ${error.message}`, 'red');
      resolve(null);
    });

    service.on('close', (code) => {
      log(name, `${name} exited with code ${code}`, 'yellow');
    });

    // Give service a moment to start
    setTimeout(() => {
      log(name, `${name} is running`, 'green');
      resolve(service);
    }, 2000);
  });
}

async function main() {
  console.log(`${colors.bright}${colors.cyan}
╔══════════════════════════════════════════════════════════════╗
║         Zein Security WAF - Development Server              ║
║         Starting all services...                             ║
╚══════════════════════════════════════════════════════════════╝
${colors.reset}`);

  // Check prerequisites
  log('SYSTEM', 'Checking prerequisites...', 'cyan');
  
  const hasDocker = await checkDocker();
  const hasGo = await checkCommand('go');
  
  // Check Python - try multiple ways (Windows prefers 'py')
  let hasPython = false;
  let pythonCmd = 'python';
  const pythonCommands = process.platform === 'win32' 
    ? ['py', 'python', 'python3'] 
    : ['python3', 'python', 'py'];
  for (const cmd of pythonCommands) {
    const found = await checkCommand(cmd);
    if (found) {
      hasPython = true;
      pythonCmd = cmd;
      break;
    }
  }
  
  const hasNode = await checkCommand('node');

  if (!hasNode) {
    log('SYSTEM', 'Node.js is required but not found!', 'red');
    process.exit(1);
  }

  if (!hasGo) {
    log('SYSTEM', 'Go is required for the backend but not found!', 'red');
    log('SYSTEM', 'Please install Go from https://golang.org/dl/', 'yellow');
  }

  if (!hasPython) {
    log('SYSTEM', 'Python is required for the AI service but not found!', 'red');
    log('SYSTEM', 'Please install Python from https://www.python.org/downloads/', 'yellow');
  }

  // Start Docker services if available
  if (hasDocker) {
    await startDockerServices();
    // Verify Docker services are running
    log('SYSTEM', 'Verifying Docker services...', 'cyan');
    await new Promise((resolve) => {
      exec('docker ps --filter "name=zein-postgres" --format "{{.Status}}"', (error, stdout) => {
        if (stdout && stdout.includes('Up')) {
          log('DOCKER', 'PostgreSQL is running', 'green');
        } else {
          log('DOCKER', 'PostgreSQL may not be ready yet', 'yellow');
        }
        resolve();
      });
    });
  } else {
    log('SYSTEM', 'Skipping Docker services. Make sure PostgreSQL and Redis are running locally.', 'yellow');
  }

  // Start all services
  log('SYSTEM', 'Starting application services...', 'cyan');

  const services = [];

  // Start AI Service (Python)
  if (hasPython) {
    // Check if dependencies are installed
    const aiServicePath = path.join(__dirname, '..', 'backend', 'ai-service');
    const requirementsPath = path.join(aiServicePath, 'requirements.txt');
    const aiPyPath = path.join(aiServicePath, 'ai.py');
    
    if (fs.existsSync(aiPyPath)) {
      // Install dependencies first if needed
      if (fs.existsSync(requirementsPath)) {
        log('AI-SERVICE', 'Checking Python dependencies...', 'cyan');
        const pipCmd = process.platform === 'win32' ? `${pythonCmd} -m pip` : 'pip3';
        
        // Check and install dependencies synchronously
        await new Promise((resolve) => {
          exec(`${pipCmd} show uvicorn fastapi`, { cwd: aiServicePath }, (error) => {
            if (error) {
              log('AI-SERVICE', 'Upgrading pip, setuptools, and wheel first...', 'cyan');
              // First upgrade pip and setuptools for Python 3.13 compatibility
              const upgradeProcess = spawn(pipCmd, ['install', '--upgrade', 'pip', 'setuptools', 'wheel'], {
                cwd: aiServicePath,
                stdio: 'inherit',
                shell: true
              });
              
              upgradeProcess.on('close', (upgradeCode) => {
                log('AI-SERVICE', 'Installing Python dependencies (this may take a minute)...', 'yellow');
                // Install dependencies without strict version requirements for Python 3.13
                const installProcess = spawn(pipCmd, ['install', 'fastapi', 'uvicorn[standard]', 'pydantic', 'numpy', 'scikit-learn', 'python-multipart'], {
                  cwd: aiServicePath,
                  stdio: 'inherit',
                  shell: true
                });
                
                installProcess.on('close', (code) => {
                  if (code === 0) {
                    log('AI-SERVICE', 'Dependencies installed successfully!', 'green');
                  } else {
                    log('AI-SERVICE', 'Failed to install dependencies. Continuing anyway...', 'yellow');
                    log('AI-SERVICE', 'Try running: scripts\\fix-python-deps.bat manually', 'yellow');
                  }
                  resolve();
                });
              });
            } else {
              log('AI-SERVICE', 'Python dependencies already installed', 'green');
              resolve();
            }
          });
        });
      }
      
      // Start AI service
      log('AI-SERVICE', `Starting AI Service with ${pythonCmd}...`, 'green');
      const aiService = await startService(
        'AI-SERVICE',
        pythonCmd,
        ['-m', 'uvicorn', 'ai:app', '--host', '0.0.0.0', '--port', '5000', '--reload'],
        aiServicePath,
        'green'
      );
      if (aiService) services.push(aiService);
    } else {
      log('AI-SERVICE', 'ai.py not found. Skipping...', 'yellow');
    }
  } else {
    log('AI-SERVICE', 'Skipped (Python not found)', 'yellow');
    if (process.platform === 'win32') {
      log('AI-SERVICE', 'On Windows, try: py -m pip install uvicorn fastapi', 'yellow');
      log('AI-SERVICE', 'Then: py -m uvicorn ai:app --host 0.0.0.0 --port 5000 --reload', 'yellow');
    } else {
      log('AI-SERVICE', 'Try: python3 -m pip install uvicorn fastapi', 'yellow');
      log('AI-SERVICE', 'Then: python3 -m uvicorn ai:app --host 0.0.0.0 --port 5000 --reload', 'yellow');
    }
  }

  // Start Backend (Go)
  if (hasGo) {
    const backendPath = path.join(__dirname, '..', 'backend');
    const mainGoPath = path.join(backendPath, 'main.go');
    
    if (fs.existsSync(mainGoPath)) {
      log('BACKEND', 'Starting Backend...', 'yellow');
      // Use 'go run .' instead of 'go run main.go' to compile all files in package
      const backend = await startService(
        'BACKEND',
        'go',
        ['run', '.'],
        backendPath,
        'yellow'
      );
      if (backend) services.push(backend);
    } else {
      log('BACKEND', 'main.go not found. Skipping...', 'yellow');
    }
  } else {
    log('BACKEND', 'Skipped (Go not found)', 'yellow');
  }

  // Start Frontend (React)
  const frontendPath = path.join(__dirname, '..', 'frontend');
  const frontendPackageJson = path.join(frontendPath, 'package.json');
  
  if (fs.existsSync(frontendPackageJson)) {
    // Check if node_modules exists
    const nodeModulesPath = path.join(frontendPath, 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) {
      log('FRONTEND', 'node_modules not found. Installing dependencies...', 'yellow');
      log('FRONTEND', 'This may take a few minutes...', 'yellow');
      
      const installProcess = spawn('npm', ['install'], {
        cwd: frontendPath,
        stdio: 'inherit',
        shell: true
      });
      
      await new Promise((resolve) => {
        installProcess.on('close', (code) => {
          if (code === 0) {
            log('FRONTEND', 'Dependencies installed successfully!', 'green');
          } else {
            log('FRONTEND', 'Failed to install dependencies. Continuing anyway...', 'yellow');
          }
          resolve();
        });
      });
    }
    
    log('FRONTEND', 'Starting Frontend...', 'magenta');
    const frontend = await startService(
      'FRONTEND',
      'npm',
      ['run', 'dev'],
      frontendPath,
      'magenta'
    );
    if (frontend) services.push(frontend);
  } else {
    log('FRONTEND', 'package.json not found. Skipping...', 'yellow');
  }

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log(`\n${colors.yellow}Shutting down all services...${colors.reset}`);
    services.forEach(service => {
      if (service) {
        service.kill('SIGTERM');
      }
    });
    if (hasDocker) {
      exec('docker-compose stop postgres redis', { cwd: path.join(__dirname, '..') });
    }
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log(`\n${colors.yellow}Shutting down all services...${colors.reset}`);
    services.forEach(service => {
      if (service) {
        service.kill('SIGTERM');
      }
    });
    if (hasDocker) {
      exec('docker-compose stop postgres redis', { cwd: path.join(__dirname, '..') });
    }
    process.exit(0);
  });

  log('SYSTEM', 'All services started! Press Ctrl+C to stop.', 'green');
  log('SYSTEM', 'Frontend: http://localhost:3000', 'cyan');
  log('SYSTEM', 'Backend API: http://localhost:8080', 'cyan');
  log('SYSTEM', 'AI Service: http://localhost:5000', 'cyan');
}

main().catch((error) => {
  log('SYSTEM', `Fatal error: ${error.message}`, 'red');
  process.exit(1);
});

