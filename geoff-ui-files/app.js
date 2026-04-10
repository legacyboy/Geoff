// Geoff UI App
document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');
    
    // Tab switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            
            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');
        });
    });
    
    // Chat functionality
    const chatBox = document.getElementById('chat-box');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    
    function addMessage(text, sender) {
        const msg = document.createElement('div');
        msg.className = `message ${sender}`;
        msg.textContent = text;
        chatBox.appendChild(msg);
        chatBox.scrollTop = chatBox.scrollHeight;
    }
    
    function sendMessage() {
        const text = messageInput.value.trim();
        if (!text) return;
        
        addMessage(text, 'user');
        messageInput.value = '';
        
        // Simulate Geoff response (replace with actual API call)
        setTimeout(() => {
            addMessage("Geoff here! DFIR analysis mode active. 🔬", 'geoff');
        }, 500);
    }
    
    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });
    
    // File upload
    const fileInput = document.getElementById('evidence-file');
    fileInput.addEventListener('change', (e) => {
        const files = Array.from(e.target.files);
        if (files.length > 0) {
            alert(`Selected ${files.length} file(s) for evidence upload`);
        }
    });
    
    // Config save
    document.getElementById('save-config').addEventListener('click', () => {
        alert('Configuration saved!');
    });
    
    // Initial greeting
    addMessage("Welcome! I'm Geoff, your DFIR assistant. Ready to analyze evidence.", 'geoff');
});
