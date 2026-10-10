from fastapi import FastAPI

app = FastAPI()

students = [
    {"id": 1, "name": "zayn", "grade": "A"},
    {"id": 2, "name": "parbat", "grade": "B"},
]

@app.get("/students")
def get_students():
    return students

@app.get("/students/{student_id}")
def get_student(student_id: int):
    for s in students:
        if s["id"] == student_id:
            return s
    return {"error": "not found"}
@app.get("/admin/reports")
def admin_reports():
    return {"report": "Secret admin-only data"}