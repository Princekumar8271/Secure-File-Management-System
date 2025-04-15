document.addEventListener('DOMContentLoaded', function() {
    // Get the canvas element
    const canvas = document.getElementById('network-canvas');
    
    // Initialize Three.js scene
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
    
    // Performance optimization - adjust for device capability
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    const isLowPerfDevice = window.navigator.hardwareConcurrency ? window.navigator.hardwareConcurrency <= 4 : isMobile;
    
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2)); // Limit pixel ratio for performance
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0); // Make background transparent to show eye background
    
    // Reduce particle count based on device performance and make it more subtle for our eye background
    const particleCount = isLowPerfDevice ? 40 : 100;
    const connectionLimit = isLowPerfDevice ? 60 : 150;
    const maxConnectionDistance = isLowPerfDevice ? 8 : 12;
    
    const particles = new THREE.BufferGeometry();
    const positions = [];
    const colors = [];
    const sizes = [];
    
    // Enhanced color palette for neurons - using red tones with more variation
    const colorPalette = [
        new THREE.Color(0xff3d4a), // Red
        new THREE.Color(0xff0000), // Bright Red
        new THREE.Color(0xC41E3A), // Cardinal Red
        new THREE.Color(0xDC143C), // Crimson
        new THREE.Color(0xA31621), // Deep Red
        new THREE.Color(0xFF5252)  // Light Red
    ];
    
    // Generate more realistic distribution of particles with more in the center
    for (let i = 0; i < particleCount; i++) {
        // Use gaussian-like distribution for more particles in the center
        let x, y, z;
        const centerBias = Math.random() < 0.7; // 70% chance to be closer to center
        
        if (centerBias) {
            // Closer to center
            x = (Math.random() - 0.5) * 30;
            y = (Math.random() - 0.5) * 30;
            z = (Math.random() - 0.5) * 30;
        } else {
            // Further from center
            x = (Math.random() - 0.5) * 60;
            y = (Math.random() - 0.5) * 60;
            z = (Math.random() - 0.5) * 60;
        }
        
        positions.push(x, y, z);
        
        // Randomly select a color from the palette
        const color = colorPalette[Math.floor(Math.random() * colorPalette.length)];
        colors.push(color.r, color.g, color.b);
        
        // Varied sizes for more depth perception
        const isCentral = Math.abs(x) < 10 && Math.abs(y) < 10 && Math.abs(z) < 10;
        const size = isCentral ? 
            Math.random() * 2.0 + 1.0 : // Larger particles in center
            Math.random() * 1.2 + 0.6;  // Smaller particles outside
        
        sizes.push(size);
    }
    
    particles.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    particles.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
    particles.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));
    
    // Create connections between neurons with improved visual
    const connections = [];
    const connectionMaterial = new THREE.LineBasicMaterial({
        color: 0xff2233,
        transparent: true,
        opacity: 0.12,
        blending: THREE.AdditiveBlending
    });
    
    // Connect nearby neurons with distance-based connections
    let connectionCount = 0;
    for (let i = 0; i < particleCount && connectionCount < connectionLimit; i++) {
        for (let j = i + 1; j < particleCount && connectionCount < connectionLimit; j++) {
            const distance = Math.sqrt(
                Math.pow(positions[i * 3] - positions[j * 3], 2) +
                Math.pow(positions[i * 3 + 1] - positions[j * 3 + 1], 2) +
                Math.pow(positions[i * 3 + 2] - positions[j * 3 + 2], 2)
            );
            
            // Create more connections for nodes near center
            const isCentralConnection = 
                Math.abs(positions[i * 3]) < 15 && 
                Math.abs(positions[i * 3 + 1]) < 15 && 
                Math.abs(positions[j * 3]) < 15 && 
                Math.abs(positions[j * 3 + 1]) < 15;
                
            const connectionThreshold = isCentralConnection ? 
                maxConnectionDistance * 1.5 : maxConnectionDistance;
                
            if (distance < connectionThreshold) {
                const geometry = new THREE.BufferGeometry();
                const linePositions = [
                    positions[i * 3], positions[i * 3 + 1], positions[i * 3 + 2],
                    positions[j * 3], positions[j * 3 + 1], positions[j * 3 + 2]
                ];
                geometry.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3));
                const line = new THREE.Line(geometry, connectionMaterial);
                scene.add(line);
                connections.push({
                    line: line,
                    startIndex: i,
                    endIndex: j,
                    distance: distance,
                    isCentral: isCentralConnection
                });
                connectionCount++;
            }
        }
    }
    
    // Create enhanced shader material for more realistic glowing neurons
    const vertexShader = isLowPerfDevice ? 
        `
            attribute float size;
            attribute vec3 color;
            varying vec3 vColor;
            
            void main() {
                vColor = color;
                vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
                gl_PointSize = size * (300.0 / -mvPosition.z);
                gl_Position = projectionMatrix * mvPosition;
            }
        ` : 
        `
            attribute float size;
            attribute vec3 color;
            varying vec3 vColor;
            uniform float time;
            
            void main() {
                vColor = color;
                vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
                
                // More organic pulsing effect
                float distanceFromCenter = length(position.xyz) * 0.05;
                float pulse = sin(time * 1.5 + distanceFromCenter * 3.0) * 0.15 + 0.85;
                
                gl_PointSize = size * pulse * (300.0 / -mvPosition.z);
                gl_Position = projectionMatrix * mvPosition;
            }
        `;
        
    const neuronMaterial = new THREE.ShaderMaterial({
        uniforms: {
            time: { value: 0 }
        },
        vertexShader: vertexShader,
        fragmentShader: `
            varying vec3 vColor;
            
            void main() {
                float distance = length(gl_PointCoord - vec2(0.5, 0.5));
                if (distance > 0.5) discard;
                
                // Softer, more realistic glow falloff
                float glow = 1.0 - smoothstep(0.2, 0.5, distance);
                float opacity = glow * 0.8;
                
                // Add slight color variation based on distance for more depth
                vec3 finalColor = vColor * (1.0 - distance * 0.4);
                
                gl_FragColor = vec4(finalColor, opacity);
            }
        `,
        transparent: true,
        blending: THREE.AdditiveBlending
    });
    
    const neuronSystem = new THREE.Points(particles, neuronMaterial);
    scene.add(neuronSystem);
    
    // Position camera for better depth
    camera.position.z = 40;
    
    // Animation variables
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;
    
    // Throttle mouse movement for performance
    let lastMouseMoveTime = 0;
    const mouseMoveThrottle = 20; // ms
    
    // Consolidated mouse movement handler for both camera movement and parallax effect
    const eyeBackground = document.querySelector('.eye-background');
    
    document.addEventListener('mousemove', (event) => {
        const now = Date.now();
        if (now - lastMouseMoveTime < mouseMoveThrottle) return;
        lastMouseMoveTime = now;
        
        // Update values for camera movement
        mouseX = (event.clientX - window.innerWidth / 2) / 100;
        mouseY = (event.clientY - window.innerHeight / 2) / 100;
        
        // Handle parallax effect if eye background exists
        if (eyeBackground) {
            const x = event.clientX / window.innerWidth;
            const y = event.clientY / window.innerHeight;
            eyeBackground.style.transform = `scale(1.05) translate(${(x - 0.5) * -10}px, ${(y - 0.5) * -10}px)`;
        }
    });
    
    // Debounce window resize for performance
    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
            renderer.setSize(window.innerWidth, window.innerHeight);
        }, 200);
    });
    
    // Store the animation frame ID so we can stop if needed
    let animationId;
    let lastFrameTime = 0;
    const frameInterval = isLowPerfDevice ? 33 : 16; // Limit to ~30fps on low-perf devices, ~60fps otherwise
    
    // Track visibility to pause animation when tab is not visible
    let isPageVisible = true;
    document.addEventListener('visibilitychange', () => {
        isPageVisible = document.visibilityState === 'visible';
        if (isPageVisible) {
            lastFrameTime = 0;
            animate();
        } else if (animationId) {
            cancelAnimationFrame(animationId);
            animationId = null;
        }
    });
    
    // Animation loop
    function animate(timestamp) {
        animationId = requestAnimationFrame(animate);
        
        // Skip frames to maintain target framerate
        if (timestamp && lastFrameTime && timestamp - lastFrameTime < frameInterval) {
            return;
        }
        lastFrameTime = timestamp || 0;
        
        // Update time uniform for pulsing effect (skip on low performance devices)
        if (!isLowPerfDevice) {
            neuronMaterial.uniforms.time.value += 0.01;
        }
        
        // Smooth camera movement following mouse - more organic motion
        targetX = mouseX * 0.3;
        targetY = mouseY * 0.3;
        camera.position.x += (targetX - camera.position.x) * 0.025;
        camera.position.y += (-targetY - camera.position.y) * 0.025;
        camera.lookAt(scene.position);
        
        // Animate connections - optimize for low performance devices
        if (!isLowPerfDevice || timestamp % 2 === 0) { // Update connections every other frame on low-perf
            const time = Date.now() * 0.0005;
            for (let i = 0; i < connections.length; i += isLowPerfDevice ? 2 : 1) { // Skip every other connection on low-perf
                const connection = connections[i];
                
                // More organic pulsing effect with distance-based variations
                const distanceFactor = 1.0 - (connection.distance / maxConnectionDistance * 0.5);
                const centralBonus = connection.isCentral ? 0.1 : 0;
                const waveSpeed = connection.isCentral ? 1.2 : 0.8;
                
                // Pulse effect on connections
                const opacity = (Math.sin(time * waveSpeed + connection.startIndex) * 0.15 + 0.25) * 0.2 * distanceFactor + centralBonus;
                connection.line.material.opacity = opacity;
            }
        }
        
        // Smoother, more organic rotation
        const time = Date.now() * 0.0005;
        neuronSystem.rotation.x = Math.sin(time * 0.3) * 0.1;
        neuronSystem.rotation.y = Math.cos(time * 0.2) * 0.1 + time * 0.05;
        
        renderer.render(scene, camera);
    }
    
    animate();
});