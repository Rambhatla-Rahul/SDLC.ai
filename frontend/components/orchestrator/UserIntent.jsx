'use client'
import React, { useEffect, useState } from 'react'
import ChatInput from '../ChatInput';

import EventLogView from '../EventLogView';

const UserIntent = ({setActiveStage}) => {
    const [inputValue, setInputValue] = useState('');
    const [messages, setMessages] = useState([]);
    const [userMessage, setUserMessage] = useState('');
    const messagesEndRef = React.useRef(null);


    const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };




    const sendUserMessage = (message) => {
        if (!message.trim()) return;

        setMessages((prev) => [
        ...prev,
        {
            sender: "user",
            message: message
        }
        ]);

        generate_random_response();
    };

    const generate_random_response = () => {
        setTimeout(() => {
        setMessages((prev) => [
            ...prev,
            {
            sender: "system",
            message: "This is a Test message from the System.",
            }
        ]);
        }, 1000);
    }

    useEffect(() => {
        const timeoutId = setTimeout(() => {
          setUserMessage(inputValue);
        }, 500);
        return () => clearTimeout(timeoutId);
    }, [inputValue]);


    useEffect(()=>{
        scrollToBottom();
    },[messages])

    useEffect(()=>{
        const lastMessage = messages[messages.length -1];
        console.log(lastMessage)
        switch (lastMessage?.message) {
            case "MOVE_TO_REQUIREMENTS":
                
                setActiveStage('requirements');
                break;
            
            case "MOVE_TO_PLANNING":
                setActiveStage('planning');
                break;
            case "MOVE_TO_DEVELOPMENT":
                setActiveStage('development');
                break;
            case "MOVE_TO_TESTING":
                setActiveStage('testing');
                break;
            case "MOVE_TO_DEPLOYMENT":
                setActiveStage('deployment');
                break;
            case "MOVE_TO_FEEDBACK":
                setActiveStage('feedback');
                break;
        
            default:
                
                
        }
    },[userMessage,setActiveStage,messages])
    return (
        <div className="flex h-full gap-4 overflow-hidden">
            
            <div className="flex-1 flex flex-col bg-zinc-900/50 rounded-xl border border-zinc-800 p-4 overflow-y-auto">
                <div 
            className="flex-1 overflow-y-auto max-h-[70vh] space-y-4 pr-2 [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-zinc-700/50 [&::-webkit-scrollbar-thumb]:rounded-full hover:[&::-webkit-scrollbar-thumb]:bg-zinc-600/50"
            >
            <EventLogView/>
            
            <div ref={messagesEndRef} />
            </div>
                <div className="pt-4 mt-auto">
                <div className="relative">
                    
                    <ChatInput onSend={sendUserMessage}/>
                    
                </div>
                </div>
            </div>
        </div>
    )
}

export default UserIntent
