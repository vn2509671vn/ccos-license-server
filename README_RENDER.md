# HƯỚNG DẪN TRIỂN KHAI CCOS LICENSE SERVER LÊN RENDER.COM

Tài liệu này cung cấp hướng dẫn chi tiết từng bước để triển khai hệ thống máy chủ bản quyền (`server/license_server.py`) của công cụ **CCOS Automation** lên nền tảng đám mây **Render.com**.

---

## 1. TỔNG QUAN KIẾN TRÚC & TÍNH NĂNG NỔI BẬT

- **Hiệu năng & Độ trễ**: Xây dựng trên nền **FastAPI** và **Uvicorn**, phản hồi xác thực key cực nhanh (< 50ms).
- **Hỗ trợ Cloud Port động**: Tự động nhận diện biến môi trường `$PORT` (mặc định cổng `10000` của Render) và lắng nghe trên `0.0.0.0`.
- **Lưu trữ dữ liệu thông minh (Dual-Engine)**:
  - **Mặc định**: Tự động dùng SQLite (`licenses.db`) cục bộ, không cần cấu hình thêm.
  - **Doanh nghiệp / Production**: Chỉ cần thêm biến môi trường `DATABASE_URL` (ví dụ: Render PostgreSQL hoặc Supabase), máy chủ tự động chuyển sang lưu trên PostgreSQL với connection pooling, bảng dữ liệu và index tự sinh tự động!
- **Bảo mật Web Admin Dashboard (`/admin`)**:
  - Trang `/admin` và toàn bộ các API quản trị (`/api/admin/*`) được bảo vệ bằng mật khẩu quản trị (`ADMIN_PASSWORD`).
  - Hỗ trợ lưu phiên đăng nhập an toàn bằng Cookie bảo mật `HttpOnly` và HMAC Signature (thời hạn 7 ngày).
  - Tích hợp nút **Đăng xuất (Logout)** an toàn ngay trên giao diện.
- **Client linh hoạt không cần Build lại Tool**:
  - Ứng dụng CCOS client tự động đọc file `config.json` nằm cùng thư mục với file `.exe`.
  - Khi đổi server từ local sang Render, chỉ cần sửa địa chỉ URL trong `config.json` là phần mềm tự động kết nối đến Render.

---

## 2. CHUẨN BỊ TRƯỚC KHI TRIỂN KHAI

1. **Tài khoản Render.com**: Đăng ký miễn phí tại [https://render.com](https://render.com).
2. **Mã nguồn**: Đã đẩy (push) repository `CCOS` lên GitHub hoặc GitLab.

---

## 3. CÁCH TRIỂN KHAI (2 PHƯƠNG PHÁP)

### PHƯƠNG PHÁP 1: Triển khai thủ công (Web Service) - Khuyên dùng

1. Đăng nhập vào Render Dashboard: [https://dashboard.render.com](https://dashboard.render.com).
2. Nhấn nút **New +** ở góc trên cùng bên phải &rarr; Chọn **Web Service**.
3. Chọn kho mã nguồn (Repository) của bạn và nhấn **Connect**.
4. Điền các trường cấu hình như sau:
   - **Name**: `ccos-license-server` (hoặc tên tuỳ ý).
   - **Region**: `Singapore` (để có tốc độ kết nối nhanh nhất từ Việt Nam) hoặc `Oregon`.
   - **Branch**: `main` (hoặc nhánh chứa code mới nhất).
   - **Root Directory**: `server`
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn license_server:app --host 0.0.0.0 --port $PORT
     ```
   - **Instance Type**: Chọn **Free** ($0/month).

5. Cấu hình biến môi trường (**Environment Variables**):
   Kéo xuống mục **Environment Variables** và nhấn **Add Environment Variable**:
   - `ADMIN_PASSWORD`: Nhập mật khẩu bạn muốn dùng để đăng nhập Web Admin (ví dụ: `MyStrongPass@2026`).
   - `SECRET_KEY`: Nhập chuỗi bảo mật ngẫu nhiên để ký số token (ví dụ: `CCOS_SECRET_89a3f2b1c7e4d567`).
   - *(Tùy chọn)* `DATABASE_URL`: Nếu bạn đã tạo Render PostgreSQL hoặc Supabase (xem mục 4 bên dưới), dán connection string vào đây.

6. Nhấn nút **Create Web Service** ở cuối trang.
7. Render sẽ tiến hành cài đặt thư viện và khởi động server. Sau khoảng 1 - 2 phút, trạng thái sẽ chuyển sang **Live** màu xanh lá.
8. URL dịch vụ của bạn sẽ có dạng: `https://ccos-license-server.onrender.com`.

---

### PHƯƠNG PHÁP 2: Triển khai 1-Click bằng Blueprint (`render.yaml`)

Trong thư mục `server/` đã có sẵn file `render.yaml`.
1. Trên Render Dashboard, nhấn **New +** &rarr; Chọn **Blueprint**.
2. Chọn repository của bạn.
3. Render sẽ tự động đọc `render.yaml` và hiển thị bản vẽ thiết lập.
4. Nhập mật khẩu quản trị cho `ADMIN_PASSWORD` và nhấn **Apply**.

---

## 4. THIẾT LẬP CƠ SỞ DỮ LIỆU POSTGRESQL (KHUYẾN NGHỊ CHO PRODUCTION)

> **Lưu ý về gói Render Free**: Trên gói Web Service Free của Render, container có thể tự khởi động lại khi không hoạt động hoặc khi deploy bản mới. Nếu dùng SQLite cục bộ, file `licenses.db` có thể bị làm mới. Do đó, để lưu trữ danh sách bản quyền vĩnh viễn, bạn nên gắn một cơ sở dữ liệu PostgreSQL.

### Lựa chọn A: Tạo PostgreSQL trực tiếp trên Render
1. Trên Render Dashboard &rarr; Nhấn **New +** &rarr; Chọn **PostgreSQL**.
2. Đặt tên: `ccos-license-db`, chọn Region `Singapore`, Plan: `Free`.
3. Nhấn **Create Database**.
4. Sau khi tạo xong, cuộn đến phần **Connections**:
   - Sao chép **Internal Database URL** (nếu Web Service cùng nằm trên Render).
   - Hoặc sao chép **External Database URL**.
5. Quay lại Web Service `ccos-license-server` &rarr; Tab **Environment** &rarr; Thêm biến:
   - Key: `DATABASE_URL`
   - Value: dán URL vừa sao chép.
6. Nhấn **Save Changes**. Server sẽ tự động kết nối và tạo bảng dữ liệu!

### Lựa chọn B: Sử dụng Supabase PostgreSQL (Miễn phí vĩnh viễn)
1. Đăng ký tài khoản miễn phí tại [https://supabase.com](https://supabase.com).
2. Tạo dự án mới và lấy chuỗi kết nối **URI** (dạng `postgresql://postgres:[PASSWORD]@...supabase.co:5432/postgres`).
3. Dán chuỗi này vào biến `DATABASE_URL` trên Render.

---

## 5. HƯỚNG DẪN SỬ DỤNG WEB ADMIN DASHBOARD

1. Mở trình duyệt và truy cập:
   ```text
   https://<ten-dich-vu-cua-ban>.onrender.com/admin
   ```
2. Giao diện đăng nhập bảo mật sẽ xuất hiện. Nhập mật khẩu quản trị viên (đã cấu hình ở `ADMIN_PASSWORD`).
3. Nhấn **Đăng Nhập Quản Trị**.
4. Sau khi đăng nhập thành công, bạn có toàn quyền:
   - **Tạo Key mới**: Nhập tên khách hàng, số ngày bản quyền (30 ngày, 90 ngày, 365 ngày...), ghi chú &rarr; Nhấn **Tạo Key Ngay**.
   - **Copy Key**: Nhấn nút `Copy` cạnh mã `CCOS-XXXX-XXXX-XXXX` để gửi cho khách hàng.
   - **Gia hạn (+30 ngày)**: Nhấn nút `+30 Ngày` để kéo dài thời hạn cho khách hàng.
   - **Khóa / Mở Khóa**: Tạm dừng hoặc mở lại quyền sử dụng của một key.
   - **Reset HWID**: Khi khách hàng thay đổi máy tính hoặc cài lại Win, nhấn `Reset HWID` để giải phóng mã máy cũ, cho phép khách hàng kích hoạt lại trên máy mới.
   - **Đăng xuất an toàn**: Nhấn nút `🚪 Đăng Xuất` ở góc trên bên phải khi hoàn tất công việc.

---

## 6. CẤU HÌNH TOOL CLIENT (`CCOS Automation Tool`) KẾT NỐI SERVER RENDER

Bạn **KHÔNG CẦN PHẢI REBUILD LẠI FILE .EXE**! Hệ thống CCOS hỗ trợ cơ chế nạp cấu hình ngoại tuyến cực kỳ tiện lợi:

1. Bên cạnh file chạy `CCOS_Automation.exe` (hoặc trong thư mục gốc của tool), tạo một file tên là `config.json`.
2. Điền nội dung như sau:
   ```json
   {
     "license_server_url": "https://<ten-dich-vu-cua-ban>.onrender.com",
     "support_contact": "Hotline / Zalo hỗ trợ: 0912.345.678"
   }
   ```
   *(Bạn cũng có thể copy từ file mẫu `config.sample.json` có sẵn trong thư mục dự án).*
3. Khởi động lại ứng dụng `CCOS_Automation.exe`. Tool sẽ tự động kết nối đến server Render để kiểm tra và kích hoạt bản quyền!

---

## 7. MẸO XỬ LÝ SỰ CỐ & SPIN-DOWN TRÊN GÓI RENDER FREE

### Hiện tượng "Spin Down" (Ngủ đông)
- **Cơ chế của Render Free**: Nếu không có truy cập trong vòng 15 phút, dịch vụ Web Service sẽ tạm thời chuyển sang trạng thái ngủ đông (Sleep).
- Khi có một request mới (ví dụ người dùng mở Tool), Render sẽ đánh thức container dậy. Thời gian khởi động mất khoảng **30 - 50 giây**.
- **Giải pháp giữ Server luôn thức (Keep-Alive miễn phí)**:
  1. Đăng ký tài khoản miễn phí tại [https://uptimerobot.com](https://uptimerobot.com) hoặc [https://cron-job.org](https://cron-job.org).
  2. Tạo một Monitor HTTP(s) mới trỏ đến:
     `https://<ten-dich-vu-cua-ban>.onrender.com/`
  3. Cài đặt tần suất ping: **Mỗi 10 phút / lần**.
  4. Server sẽ luôn luôn thức và phản hồi ngay lập tức mọi lúc 24/7!
