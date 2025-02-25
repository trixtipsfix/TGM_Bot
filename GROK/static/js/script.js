document.addEventListener('DOMContentLoaded', () => {
    const setupForm = document.getElementById('setup-form');
    let setupData = null; // Store initial setup data
    let phoneCodeHash = null; // Store phone_code_hash

    if (setupForm) {
        setupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            setupData = Object.fromEntries(formData);

            // Submit configuration
            const setupResponse = await fetch('/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(setupData)
            });

            if (!setupResponse.ok) {
                alert('Failed to save configuration');
                return;
            }

            // Initiate Telegram auth
            const authResponse = await fetch('/telegram_auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(setupData)
            });
            const result = await authResponse.json();

            if (result.status === 'code_required') {
                phoneCodeHash = result.phone_code_hash; // Store the hash
                document.getElementById('code-input').style.display = 'block';
            } else if (result.chats) {
                showChatSelection(result.chats);
            } else if (result.error) {
                alert(`Authentication error: ${result.error}`);
            }
        });

        document.getElementById('submit-code')?.addEventListener('click', async () => {
            const code = document.getElementById('verification-code').value;
            if (!code) {
                alert('Please enter the verification code');
                return;
            }
            if (!phoneCodeHash) {
                alert('Authentication session expired. Please resubmit the form.');
                return;
            }

            // Send code and phone_code_hash
            const authData = { code, phone_code_hash: phoneCodeHash };
            const response = await fetch('/telegram_auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(authData)
            });
            const result = await response.json();

            if (result.chats) {
                showChatSelection(result.chats);
            } else if (result.error) {
                alert(`Authentication error: ${result.error}`);
            }
        });

        document.getElementById('save-chats')?.addEventListener('click', async () => {
            const sourceChats = Array.from(document.querySelectorAll('input[name="source"]:checked'))
                .map(input => parseInt(input.value));
            const destChat = parseInt(document.querySelector('input[name="dest"]:checked')?.value);
            
            if (!sourceChats.length || !destChat) {
                alert('Please select at least one source chat and one destination chat');
                return;
            }

            const response = await fetch('/save_chats', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ source_chats: sourceChats, dest_chat: destChat })
            });

            if (response.ok) {
                window.location.href = '/dashboard';
            } else {
                alert('Failed to save chat configuration');
            }
        });
    }

    function showChatSelection(chats) {
        const chatList = document.getElementById('chat-list');
        chatList.innerHTML = `
            <h3>Source Chats (select multiple):</h3>
            ${chats.map(chat => `
                <label>
                    <input type="checkbox" name="source" value="${chat.id}">
                    ${chat.name}
                </label>
            `).join('')}
            <h3>Destination Chat (select one):</h3>
            ${chats.map(chat => `
                <label>
                    <input type="radio" name="dest" value="${chat.id}">
                    ${chat.name}
                </label>
            `).join('')}
        `;
        document.getElementById('chat-selection').style.display = 'block';
        document.getElementById('code-input').style.display = 'none'; // Hide code input after success
    }
});