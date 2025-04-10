document.addEventListener('DOMContentLoaded', function() {
    // Get the canvas element
    const canvas = document.getElementById('network-canvas');
    
    // Initialize Three.js scene
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x050a14, 1);
    
    // Create particles for neurons
    const particleCount = 150;
    const particles = new THREE.BufferGeometry();
    const positions = [];
    const colors = [];
    const sizes = [];
    
    // Color palette for neurons
    const colorPalette = [
        new THREE.Color(0x00e5ff), // Cyan
        new THREE.Color(0x2979ff), // Blue
        new THREE.Color(0xff3d4a), // Red
        new THREE.Color(0xff7b25)  // Orange
    ];
    
    // Generate random positions for neurons
    for (let i = 0; i < particleCount; i++) {
        const x = (Math.random() - 0.5) * 50;
        const y = (Math.random() - 0.5) * 50;
        const z = (Math.random() - 0.5) * 50;
        
        positions.push(x, y, z);
        
        // Randomly select a color from the palette
        const color = colorPalette[Math.floor(Math.random() * colorPalette.length)];
        colors.push(color.r, color.g, color.b);
        
        // Random size for each neuron
        sizes.push(Math.random() * 2 + 0.5);
    }
    
    particles.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    particles.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
    particles.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));
    
    // Create connections between neurons
    const connections = [];
    const connectionMaterial = new THREE.LineBasicMaterial({
        color: 0x00e5ff,
        transparent: true,
        opacity: 0.2,
        blending: THREE.AdditiveBlending
    });
    
    // Connect nearby neurons
    for (let i = 0; i < particleCount; i++) {
        for (let j = i + 1; j < particleCount; j++) {
            const distance = Math.sqrt(
                Math.pow(positions[i * 3] - positions[j * 3], 2) +
                Math.pow(positions[i * 3 + 1] - positions[j * 3 + 1], 2) +
                Math.pow(positions[i * 3 + 2] - positions[j * 3 + 2], 2)
            );
            
            if (distance < 10) {
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
                    endIndex: j
                });
            }
        }
    }
    
    // Create shader material for glowing neurons
    const neuronMaterial = new THREE.ShaderMaterial({
        uniforms: {
            time: { value: 0 }
        },
        vertexShader: `
            attribute float size;
            attribute vec3 color;
            varying vec3 vColor;
            uniform float time;
            
            void main() {
                vColor = color;
                vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
                float pulse = sin(time * 2.0 + position.x + position.y + position.z) * 0.1 + 0.9;
                gl_PointSize = size * pulse * (300.0 / -mvPosition.z);
                gl_Position = projectionMatrix * mvPosition;
            }
        `,
        fragmentShader: `
            varying vec3 vColor;
            
            void main() {
                float distance = length(gl_PointCoord - vec2(0.5, 0.5));
                if (distance > 0.5) discard;
                float opacity = 1.0 - smoothstep(0.3, 0.5, distance);
                gl_FragColor = vec4(vColor, opacity);
            }
        `,
        transparent: true,
        blending: THREE.AdditiveBlending
    });
    
    const neuronSystem = new THREE.Points(particles, neuronMaterial);
    scene.add(neuronSystem);
    
    // Position camera
    camera.position.z = 30;
    
    // Animation variables
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;
    
    // Handle mouse movement
    document.addEventListener('mousemove', (event) => {
        mouseX = (event.clientX - window.innerWidth / 2) / 100;
        mouseY = (event.clientY - window.innerHeight / 2) / 100;
    });
    
    // Handle window resize
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
    
    // Animation loop
    function animate() {
        requestAnimationFrame(animate);
        
        // Update time uniform for pulsing effect
        neuronMaterial.uniforms.time.value += 0.01;
        
        // Smooth camera movement following mouse
        targetX = mouseX * 0.2;
        targetY = mouseY * 0.2;
        camera.position.x += (targetX - camera.position.x) * 0.05;
        camera.position.y += (-targetY - camera.position.y) * 0.05;
        camera.lookAt(scene.position);
        
        // Animate connections
        connections.forEach(connection => {
            const startIndex = connection.startIndex;
            const endIndex = connection.endIndex;
            const time = Date.now() * 0.001;
            
            // Pulse effect on connections
            const opacity = (Math.sin(time + startIndex) * 0.3 + 0.7) * 0.3;
            connection.line.material.opacity = opacity;
        });
        
        // Slowly rotate the entire scene
        neuronSystem.rotation.x += 0.0005;
        neuronSystem.rotation.y += 0.0003;
        
        renderer.render(scene, camera);
    }
    
    animate();
});