const fs = require('fs-extra');
const path = require('path');

// Paths
const buildDir = path.join(__dirname, 'build');
const staticFiles = ['index.html', 'styles.css', 'script.js'];

async function build() {
    try {
        // Clean and create build directory
        await fs.remove(buildDir);
        await fs.ensureDir(buildDir);

        // Copy static files
        for (const file of staticFiles) {
            await fs.copy(
                path.join(__dirname, file),
                path.join(buildDir, file)
            );
        }

        console.log('Build completed successfully!');
    } catch (error) {
        console.error('Build failed:', error);
        process.exit(1);
    }
}

build();
