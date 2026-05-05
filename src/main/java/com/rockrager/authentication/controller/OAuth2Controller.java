package com.rockrager.authentication.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class OAuth2Controller {

    @GetMapping("/oauth2/redirect")
    @ResponseBody
    public String oauth2Redirect(
            @RequestParam("accessToken") String accessToken,
            @RequestParam("refreshToken") String refreshToken) {

        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Google Login Success</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    margin: 0;
                }
                .container {
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    max-width: 600px;
                    text-align: center;
                }
                h1 { color: #333; }
                .success { color: #4CAF50; font-size: 48px; margin-bottom: 20px; }
                .token-box {
                    background: #f5f5f5;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                    word-break: break-all;
                    text-align: left;
                }
                .label { font-weight: bold; color: #555; }
                button {
                    background: #667eea;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                    margin-top: 10px;
                }
                button:hover { background: #5a67d8; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success">✓</div>
                <h1>Google Login Successful!</h1>
                <p>You have successfully logged in with Google.</p>
                
                <div class="token-box">
                    <div class="label">Access Token:</div>
                    <code>%s</code>
                </div>
                
                <div class="token-box">
                    <div class="label">Refresh Token:</div>
                    <code>%s</code>
                </div>
                
                <p>You can now use these tokens for API requests.</p>
                <button onclick="copyToClipboard()">Copy Access Token</button>
            </div>
            
            <script>
                function copyToClipboard() {
                    const token = '%s';
                    navigator.clipboard.writeText(token);
                    alert('Access token copied to clipboard!');
                }
                
                // Store tokens in localStorage for later use
                localStorage.setItem('accessToken', '%s');
                localStorage.setItem('refreshToken', '%s');
                console.log('Tokens saved to localStorage');
            </script>
        </body>
        </html>
        """.formatted(accessToken, refreshToken, accessToken, accessToken, refreshToken);
    }
}