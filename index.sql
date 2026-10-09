-- ==========================================
-- SETUP SCRIPT: AR Courseware (Ng31241)
-- ==========================================

-- 1. สร้างตารางพื้นฐาน
CREATE TABLE teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE students (
    id VARCHAR(11) PRIMARY KEY,
    title VARCHAR(20) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    section VARCHAR(10) NOT NULL,
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    kind VARCHAR(4) CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, kind)
);

CREATE TABLE progress (
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    done BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY(user_id, unit)
);

CREATE TABLE submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score INTEGER NULL,
    teacher_comment TEXT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. ฟังก์ชันตรวจสอบสิทธิ์ (Security Definer)
CREATE OR REPLACE FUNCTION public.is_teacher() 
RETURNS BOOLEAN 
SECURITY DEFINER SET search_path = public
LANGUAGE plpgsql AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM teachers WHERE user_id = auth.uid());
END;
$$;

-- 3. เปิด RLS
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE materials ENABLE ROW LEVEL SECURITY;

-- Revoke จาก anon
REVOKE ALL ON teachers, students, attempts, progress, submissions, materials FROM anon;

-- 4. RLS Policies
-- Teachers: ครูเห็นของตัวเอง
CREATE POLICY "Teacher read own" ON teachers FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- Students: นร.เห็นข้อมูลตัวเอง, ครูเห็นทั้งหมด
CREATE POLICY "Student select own or teacher" ON students FOR SELECT TO authenticated 
USING (auth.uid() = user_id OR public.is_teacher());
-- นร. แก้ไขข้อมูลตัวเองได้ (จะถูกจำกัดคอลัมน์ด้วย Trigger)
CREATE POLICY "Student update own" ON students FOR UPDATE TO authenticated 
USING (auth.uid() = user_id);

-- Attempts: นร.เห็น/เพิ่มของตัวเอง, ครูเห็นทั้งหมด
CREATE POLICY "Attempt select" ON attempts FOR SELECT TO authenticated 
USING (auth.uid() = user_id OR public.is_teacher());
CREATE POLICY "Attempt insert" ON attempts FOR INSERT TO authenticated 
WITH CHECK (auth.uid() = user_id);

-- Progress: เหมือน Attempts แต่ให้อัปเดตได้
CREATE POLICY "Progress select" ON progress FOR SELECT TO authenticated 
USING (auth.uid() = user_id OR public.is_teacher());
CREATE POLICY "Progress insert" ON progress FOR INSERT TO authenticated 
WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Progress update" ON progress FOR UPDATE TO authenticated 
USING (auth.uid() = user_id);

-- Submissions: นร.เห็น/เพิ่ม/แก้(บางส่วน)ของตัวเอง, ครูเห็น/แก้(ตรวจงาน)ได้ทั้งหมด
CREATE POLICY "Submission select" ON submissions FOR SELECT TO authenticated 
USING (auth.uid() = user_id OR public.is_teacher());
CREATE POLICY "Submission insert" ON submissions FOR INSERT TO authenticated 
WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Submission update" ON submissions FOR UPDATE TO authenticated 
USING (auth.uid() = user_id OR public.is_teacher());

-- Materials: ทุกคน(auth)เห็น, เฉพาะครูที่จัดการได้
CREATE POLICY "Material select" ON materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Material insert" ON materials FOR INSERT TO authenticated WITH CHECK (public.is_teacher());
CREATE POLICY "Material update" ON materials FOR UPDATE TO authenticated USING (public.is_teacher());
CREATE POLICY "Material delete" ON materials FOR DELETE TO authenticated USING (public.is_teacher());

-- 5. Triggers ควบคุมความปลอดภัยระดับข้อมูล
-- 5.1 ควบคุมไม่ให้นักเรียนแก้คะแนน submissions ของตัวเอง
CREATE OR REPLACE FUNCTION protect_submission_evaluation()
RETURNS TRIGGER 
SECURITY DEFINER SET search_path = public
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT public.is_teacher() THEN
        NEW.score = OLD.score;
        NEW.teacher_comment = OLD.teacher_comment;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER submission_protection BEFORE UPDATE ON submissions
FOR EACH ROW EXECUTE FUNCTION protect_submission_evaluation();

-- 5.2 ควบคุมให้นักเรียนแก้ได้เฉพาะ photo_path ในตาราง students
CREATE OR REPLACE FUNCTION protect_student_columns()
RETURNS TRIGGER 
SECURITY DEFINER SET search_path = public
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT public.is_teacher() THEN
        NEW.id = OLD.id;
        NEW.title = OLD.title;
        NEW.first_name = OLD.first_name;
        NEW.last_name = OLD.last_name;
        NEW.section = OLD.section;
        NEW.user_id = OLD.user_id;
        NEW.created_at = OLD.created_at;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER student_column_protection BEFORE UPDATE ON students
FOR EACH ROW EXECUTE FUNCTION protect_student_columns();

-- 5.3 ผูกบัญชี auth.users กับรายชื่อ students
CREATE OR REPLACE FUNCTION check_student_signup()
RETURNS TRIGGER
SECURITY DEFINER SET search_path = public
LANGUAGE plpgsql AS $$
DECLARE
    extracted_id VARCHAR(11);
    student_record RECORD;
BEGIN
    -- เช็คว่าเป็นอีเมลนักเรียนหรือไม่ (ขึ้นต้นด้วยตัวเลข 11 หลัก)
    IF NEW.email ~ '^[0-9]{11}@' THEN
        extracted_id := SUBSTRING(NEW.email FROM '^[0-9]{11}');
        
        -- ตรวจสอบว่ามีในระบบและยังไม่ถูกใช้
        SELECT * INTO student_record FROM students WHERE id = extracted_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'ไม่พบรหัสนักศึกษานี้ในรายวิชา';
        END IF;
        IF student_record.user_id IS NOT NULL THEN
            RAISE EXCEPTION 'รหัสนักศึกษานี้ถูกลงทะเบียนไปแล้ว';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trigger_check_student_signup BEFORE INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION check_student_signup();

-- อัปเดต user_id กลับไปยังตาราง students หลังสมัครสำเร็จ
CREATE OR REPLACE FUNCTION link_student_user_id()
RETURNS TRIGGER
SECURITY DEFINER SET search_path = public
LANGUAGE plpgsql AS $$
DECLARE
    extracted_id VARCHAR(11);
BEGIN
    IF NEW.email ~ '^[0-9]{11}@' THEN
        extracted_id := SUBSTRING(NEW.email FROM '^[0-9]{11}');
        UPDATE students SET user_id = NEW.id WHERE id = extracted_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trigger_link_student_user_id AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION link_student_user_id();

-- 6. มุมมอง (View) สำหรับผู้สอน
CREATE VIEW results WITH (security_invoker = true) AS
SELECT 
    s.id, s.title, s.first_name, s.last_name, s.section, s.photo_path,
    (SELECT score FROM attempts WHERE user_id = s.user_id AND kind = 'pre') as pre_score,
    (SELECT score FROM attempts WHERE user_id = s.user_id AND kind = 'post') as post_score,
    (SELECT COUNT(*) FROM progress WHERE user_id = s.user_id AND done = true) as units_completed,
    s.user_id
FROM students s;

-- 7. ตั้งค่า Storage Buckets (ใส่ JSON config กำหนดชนิดและขนาดไฟล์)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES 
('photos', 'photos', false, 2097152, ARRAY['image/png', 'image/jpeg', 'image/jpg']),
('submissions', 'submissions', false, 20971520, ARRAY['image/png', 'image/jpeg', 'application/pdf', 'video/mp4']),
('materials', 'materials', false, 52428800, ARRAY['application/pdf', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']);

-- นโยบาย Storage
-- Photos: นร.สร้าง/แก้ในโฟลเดอร์รหัสตัวเอง (UID), ครูอ่านได้ทั้งหมด, นร.อ่านของตัวเอง
CREATE POLICY "Photos insert" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Photos update" ON storage.objects FOR UPDATE TO authenticated USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Photos select" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND (public.is_teacher() OR (storage.foldername(name))[1] = auth.uid()::text));

-- Submissions: โครงสร้างเหมือน Photos
CREATE POLICY "Submissions insert" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Submissions select" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND (public.is_teacher() OR (storage.foldername(name))[1] = auth.uid()::text));

-- Materials: ครูจัดการได้ นร.อ่านได้อย่างเดียว
CREATE POLICY "Materials select" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "Materials insert" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'materials' AND public.is_teacher());
CREATE POLICY "Materials delete" ON storage.objects FOR DELETE TO authenticated USING (bucket_id = 'materials' AND public.is_teacher());

-- 8. ข้อมูลจำลองรายชื่อนักเรียน (นำเข้าจริงผ่าน CSV Table Editor ได้)
INSERT INTO students (id, title, first_name, last_name, section) VALUES
('11111111111', 'นาย', 'สมชาย', 'เรียนดี', '4/1'),
('11111111112', 'นางสาว', 'สมหญิง', 'ขยันยิ่ง', '4/1'),
('11111111113', 'นาย', 'มานะ', 'อดทน', '4/1'),
('11111111114', 'นางสาว', 'มานี', 'มีสติ', '4/2'),
('11111111115', 'นาย', 'ปิติ', 'ยินดี', '4/2'),
('11111111116', 'นางสาว', 'ชูใจ', 'ใฝ่รู้', '4/2');

-- ==========================================
-- คำสั่งสำหรับตั้งค่าผู้สอน (ครู)
-- ==========================================
-- วิธีใช้: เมื่อครูสมัครสมาชิกด้วยอีเมลปกติ (ไม่ใช่รหัส 11 หลัก) เสร็จแล้ว 
-- ให้นำ UUID ของครูจากตาราง auth.users มาใส่ในคำสั่งด้านล่าง แล้วเอาเครื่องหมาย -- ออกเพื่อรัน
--
-- INSERT INTO teachers (user_id) 
-- VALUES ('ใส่-UUID-ของครูที่นี่');