@echo off

echo Starting backend...
cd backend
start cmd /k uvicorn main:app --reload --port 8003

echo Starting frontend...
cd ../frontend
start cmd /k npm run dev