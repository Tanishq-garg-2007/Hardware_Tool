import React, { useState, useEffect, useRef } from 'react';
import {
    Box, Typography, Paper, TextField, IconButton,
    List, ListItem, Avatar, Fab, Zoom, Button, Stack, Tooltip
} from '@mui/material';

import {
    Chat as ChatIcon,
    Minimize as MinimizeIcon,
    Close as CloseIcon,
    Send as SendIcon,
    ExpandLess as MaximizeIcon,
    Fullscreen as FullscreenIcon,
    FullscreenExit as FullscreenExitIcon
} from '@mui/icons-material';

// Helper to compile **bold** and `code` inline spans
function renderInlineFormatted(text) {
    if (!text) return null;
    const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    return parts.map((part, i) => {
        if (part.startsWith('**') && part.endsWith('**')) {
            return <strong key={i} style={{ fontWeight: 600, color: 'inherit' }}>{part.slice(2, -2)}</strong>;
        }
        if (part.startsWith('`') && part.endsWith('`')) {
            return (
                <Box
                    component="span"
                    key={i}
                    sx={{
                        fontFamily: 'monospace',
                        bgcolor: 'rgba(0,0,0,0.06)',
                        px: 0.75,
                        py: 0.2,
                        borderRadius: '4px',
                        fontSize: '0.85em',
                        color: '#2563EB',
                        border: '1px solid rgba(0,0,0,0.08)'
                    }}
                >
                    {part.slice(1, -1)}
                </Box>
            );
        }
        return part;
    });
}

// Markdown Formatter Component to compile structured LLM responses
const FormattedMessage = ({ text, isUser }) => {
    if (isUser) {
        return <Typography variant="body2" sx={{ color: 'white', whiteSpace: 'pre-wrap' }}>{text}</Typography>;
    }

    const lines = text.split('\n');
    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.6, fontSize: '0.9rem', lineHeight: 1.6, color: '#0F172A' }}>
            {lines.map((line, idx) => {
                const trimmed = line.trim();
                if (!trimmed) return <Box key={idx} sx={{ height: 4 }} />;

                // Heading 3 or 4 (### or ####)
                if (trimmed.startsWith('### ') || trimmed.startsWith('#### ')) {
                    const headingText = trimmed.replace(/^#+\s*/, '');
                    return (
                        <Typography key={idx} variant="subtitle2" sx={{ fontWeight: 700, mt: 1, mb: 0.2, color: '#2563EB' }}>
                            {headingText}
                        </Typography>
                    );
                }

                // Heading 1 or 2 (# or ##)
                if (trimmed.startsWith('# ') || trimmed.startsWith('## ')) {
                    const headingText = trimmed.replace(/^#+\s*/, '');
                    return (
                        <Typography key={idx} variant="subtitle1" sx={{ fontWeight: 700, mt: 1.5, mb: 0.5, color: '#0F172A', borderBottom: '1px solid #E2E8F0', pb: 0.25 }}>
                            {headingText}
                        </Typography>
                    );
                }

                // Bullet point (*, -, or numbered 1.)
                const bulletMatch = trimmed.match(/^(\*|-|\d+\.)\s+(.+)$/);
                if (bulletMatch) {
                    const content = bulletMatch[2];
                    return (
                        <Box key={idx} sx={{ display: 'flex', alignItems: 'flex-start', pl: 1, gap: 1 }}>
                            <Typography component="span" sx={{ color: '#2563EB', fontWeight: 'bold', lineHeight: 1.4 }}>•</Typography>
                            <Typography variant="body2" component="div" sx={{ flexGrow: 1, color: '#0F172A' }}>
                                {renderInlineFormatted(content)}
                            </Typography>
                        </Box>
                    );
                }

                // Standard paragraph
                return (
                    <Typography key={idx} variant="body2" component="div" sx={{ color: '#0F172A' }}>
                        {renderInlineFormatted(trimmed)}
                    </Typography>
                );
            })}
        </Box>
    );
};

const ChatBot = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [isMinimized, setIsMinimized] = useState(false);
    const [isExpanded, setIsExpanded] = useState(false);
    const [chatInput, setChatInput] = useState("");
    const [selectedModel, setSelectedModel] = useState("qwen3.5:0.8b");

    // Only 2 new models as requested
    const availableModels = [
        { label: "Qwen 3.5 0.8B", value: "qwen3.5:0.8b" },
        { label: "LFM 2.5 Thinking 1.2B", value: "lfm2.5-thinking:1.2b" }
    ];

    const [messages, setMessages] = useState([
        { role: "assistant", content: "Hello! I'm the IoT Security Lab Assistant. How can I assist you with hardware auditing, SPI flash extraction, boot logs, or voltage glitching today?" }
    ]);

    const messagesEndRef = useRef(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages, isMinimized, isExpanded]);

    const handleSendMessage = async () => {
        if (!chatInput.trim()) return;

        const userMessage = { role: "user", content: chatInput };
        setChatInput("");

        setMessages(prev => [
            ...prev,
            userMessage,
            { role: "assistant", content: "Analyzing...", loading: true }
        ]);

        try {
            // Call Backend RAG Assistant Endpoint
            const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/assistant/chat`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    query: userMessage.content,
                    model: selectedModel
                })
            });

            if (response.ok) {
                const data = await response.json();
                setMessages(prev => {
                    const copy = [...prev];
                    copy[copy.length - 1] = {
                        role: "assistant",
                        content: data.answer || "No response received.",
                        loading: false
                    };
                    return copy;
                });
                return;
            }

            // Fallback: Direct Ollama streaming
            const ollamaRes = await fetch("http://localhost:11434/api/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    model: selectedModel,
                    messages: [...messages, userMessage].map(m => ({
                        role: m.role,
                        content: m.content
                    })),
                    stream: true
                })
            });

            if (!ollamaRes.ok) throw new Error("Connection failed");

            const reader = ollamaRes.body.getReader();
            const decoder = new TextDecoder();
            let accumulated = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split("\n");

                for (const line of lines) {
                    if (!line.trim()) continue;
                    const json = JSON.parse(line);
                    if (json?.message?.content) {
                        accumulated += json.message.content;
                        setMessages(prev => {
                            const copy = [...prev];
                            copy[copy.length - 1] = {
                                role: "assistant",
                                content: accumulated,
                                loading: false
                            };
                            return copy;
                        });
                    }
                }
            }
        } catch (err) {
            setMessages(prev => {
                const copy = [...prev];
                copy[copy.length - 1] = {
                    role: "assistant",
                    content: "❌ Failed to connect to Assistant backend or Ollama. Ensure backend/Ollama are running.",
                    loading: false
                };
                return copy;
            });
        }
    };

    return (
        <Box sx={{ position: "fixed", bottom: 24, right: 24, zIndex: 3000 }}>
            {!isOpen && (
                <Zoom in>
                    <Fab 
                        color="primary" 
                        onClick={() => setIsOpen(true)} 
                        sx={{ 
                            width: 65, 
                            height: 65,
                            boxShadow: "0 8px 30px rgba(37, 99, 235, 0.35)",
                            bgcolor: "primary.main",
                            "&:hover": { bgcolor: "#1d4ed8" }
                        }}
                    >
                        <ChatIcon sx={{ fontSize: 30 }} />
                    </Fab>
                </Zoom>
            )}

            {isOpen && (
                <Paper elevation={16} sx={{
                    width: isExpanded ? "min(820px, 92vw)" : 390,
                    height: isMinimized ? "auto" : (isExpanded ? "min(780px, 86vh)" : 520),
                    display: "flex",
                    flexDirection: "column",
                    borderRadius: 4,
                    overflow: "hidden",
                    border: "1px solid #E2E8F0",
                    boxShadow: isExpanded 
                        ? "0 20px 60px rgba(15, 23, 42, 0.25)" 
                        : "0 10px 40px rgba(15, 23, 42, 0.15)",
                    transition: "width 0.25s ease, height 0.25s ease"
                }}>
                    {/* HEADER */}
                    <Box sx={{
                        bgcolor: "#0F172A",
                        color: "white",
                        px: 2.5,
                        py: 1.75,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        borderBottom: "1px solid rgba(255,255,255,0.1)"
                    }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                            <Avatar sx={{ width: 34, height: 34, bgcolor: "primary.main", fontSize: "0.85rem", fontWeight: 700 }}>
                                AI
                            </Avatar>

                            <Box>
                                <Typography variant="subtitle2" sx={{ fontWeight: 700, letterSpacing: "-0.3px", fontSize: "0.95rem" }}>
                                    IoT Lab Assistant
                                </Typography>

                                {/* 2 MODELS SWITCHER */}
                                <Stack direction="row" spacing={0.75} sx={{ mt: 0.5 }}>
                                    {availableModels.map(model => (
                                        <Button
                                            key={model.value}
                                            size="small"
                                            onClick={() => setSelectedModel(model.value)}
                                            variant={selectedModel === model.value ? "contained" : "outlined"}
                                            disabled={messages.at(-1)?.loading}
                                            sx={{
                                                fontSize: "0.68rem",
                                                px: 1.25,
                                                py: 0.2,
                                                minHeight: 22,
                                                borderRadius: "10px",
                                                textTransform: "none",
                                                fontWeight: 600,
                                                bgcolor: selectedModel === model.value ? "primary.main" : "transparent",
                                                color: "white",
                                                borderColor: selectedModel === model.value ? "primary.main" : "rgba(255,255,255,0.3)",
                                                "&:hover": {
                                                    borderColor: "white",
                                                    bgcolor: selectedModel === model.value ? "#1d4ed8" : "rgba(255,255,255,0.08)"
                                                }
                                            }}
                                        >
                                            {model.label}
                                        </Button>
                                    ))}
                                </Stack>
                            </Box>
                        </Box>

                        {/* WINDOW CONTROLS (EXPAND, MINIMIZE, CLOSE) */}
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <Tooltip title={isExpanded ? "Collapse Window" : "Expand to Read Easily"}>
                                <IconButton 
                                    size="small" 
                                    color="inherit" 
                                    onClick={() => {
                                        setIsExpanded(!isExpanded);
                                        if (isMinimized) setIsMinimized(false);
                                    }}
                                    sx={{ opacity: 0.85, "&:hover": { opacity: 1, bgcolor: "rgba(255,255,255,0.1)" } }}
                                >
                                    {isExpanded ? <FullscreenExitIcon fontSize="small" /> : <FullscreenIcon fontSize="small" />}
                                </IconButton>
                            </Tooltip>
                            <Tooltip title={isMinimized ? "Maximize" : "Minimize"}>
                                <IconButton 
                                    size="small" 
                                    color="inherit" 
                                    onClick={() => setIsMinimized(!isMinimized)}
                                    sx={{ opacity: 0.85, "&:hover": { opacity: 1, bgcolor: "rgba(255,255,255,0.1)" } }}
                                >
                                    {isMinimized ? <MaximizeIcon fontSize="small" /> : <MinimizeIcon fontSize="small" />}
                                </IconButton>
                            </Tooltip>
                            <Tooltip title="Close">
                                <IconButton 
                                    size="small" 
                                    color="inherit" 
                                    onClick={() => setIsOpen(false)}
                                    sx={{ opacity: 0.85, "&:hover": { opacity: 1, bgcolor: "rgba(255,255,255,0.1)" } }}
                                >
                                    <CloseIcon fontSize="small" />
                                </IconButton>
                            </Tooltip>
                        </Box>
                    </Box>

                    {!isMinimized && (
                        <>
                            {/* CHAT BODY */}
                            <Box sx={{ 
                                flexGrow: 1, 
                                p: isExpanded ? 3 : 2, 
                                overflowY: "auto", 
                                bgcolor: "#F8FAFC" 
                            }}>
                                <List sx={{ p: 0 }}>
                                    {messages.map((msg, idx) => (
                                        <ListItem key={idx} sx={{
                                            justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                                            px: 0,
                                            mb: 1.5
                                        }}>
                                            <Paper sx={{
                                                p: isExpanded ? 2.25 : 1.75,
                                                bgcolor: msg.role === "user" ? "primary.main" : "white",
                                                maxWidth: isExpanded ? "85%" : "90%",
                                                borderRadius: msg.role === "user"
                                                    ? "18px 18px 4px 18px"
                                                    : "18px 18px 18px 4px",
                                                boxShadow: msg.role === "user"
                                                    ? "0 4px 12px rgba(37, 99, 235, 0.2)"
                                                    : "0 2px 10px rgba(0,0,0,0.04)",
                                                border: msg.role === "user" ? "none" : "1px solid #E2E8F0"
                                            }}>
                                                <FormattedMessage text={msg.content} isUser={msg.role === "user"} />
                                            </Paper>
                                        </ListItem>
                                    ))}
                                    <div ref={messagesEndRef} />
                                </List>
                            </Box>

                            {/* INPUT SECTION */}
                            <Box sx={{ 
                                p: isExpanded ? 2.5 : 1.75, 
                                display: "flex", 
                                gap: 1.25,
                                bgcolor: "white",
                                borderTop: "1px solid #E2E8F0"
                            }}>
                                <TextField
                                    fullWidth
                                    size="small"
                                    value={chatInput}
                                    onChange={e => setChatInput(e.target.value)}
                                    onKeyPress={e => e.key === "Enter" && handleSendMessage()}
                                    placeholder="Ask about hardware steps, UART, SPI, boot logs..."
                                    sx={{
                                        "& .MuiOutlinedInput-root": {
                                            borderRadius: "12px",
                                            bgcolor: "#F8FAFC"
                                        }
                                    }}
                                />
                                <IconButton
                                    onClick={handleSendMessage}
                                    disabled={!chatInput.trim()}
                                    sx={{ 
                                        bgcolor: "primary.main", 
                                        color: "white",
                                        borderRadius: "12px",
                                        px: 1.75,
                                        "&:hover": { bgcolor: "#1d4ed8" },
                                        "&.Mui-disabled": { bgcolor: "#E2E8F0", color: "#94A3B8" }
                                    }}
                                >
                                    <SendIcon fontSize="small" />
                                </IconButton>
                            </Box>
                        </>
                    )}
                </Paper>
            )}
        </Box>
    );
};

export default ChatBot;

