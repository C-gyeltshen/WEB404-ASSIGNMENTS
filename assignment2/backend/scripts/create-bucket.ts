/**
 * Creates (or updates) the PRIVATE Supabase Storage bucket over REST, with
 * bucket-level limits as a second line of defence behind the API's own checks.
 * Run: npm run storage:setup
 */
import "dotenv/config";

const url = process.env.SUPABASE_URL!.replace(/\/+$/, "");
const key = process.env.SUPABASE_SECRET_KEY!;
const bucket = process.env.SUPABASE_STORAGE_BUCKET!;
const maxMb = Number(process.env.MAX_FILE_SIZE_MB ?? 5);

const headers: Record<string, string> = { apikey: key, "Content-Type": "application/json" };
if (key.startsWith("eyJ")) headers.Authorization = `Bearer ${key}`;

const config = {
  public: false, // objects are reachable ONLY through signed URLs the API creates
  file_size_limit: Math.floor(maxMb * 1024 * 1024),
  allowed_mime_types: ["image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf"],
};

let res = await fetch(`${url}/storage/v1/bucket`, {
  method: "POST",
  headers,
  body: JSON.stringify({ id: bucket, name: bucket, ...config }),
});

if (!res.ok) {
  const text = await res.text();
  if (!/already exists|Duplicate|409/i.test(text + res.status)) {
    console.error(`Failed to create bucket: ${res.status} ${text}`);
    process.exit(1);
  }
  res = await fetch(`${url}/storage/v1/bucket/${bucket}`, {
    method: "PUT",
    headers,
    body: JSON.stringify(config),
  });
  if (!res.ok) {
    console.error(`Failed to update bucket: ${res.status} ${await res.text()}`);
    process.exit(1);
  }
  console.log(`Bucket "${bucket}" already existed: settings updated (private, ${maxMb} MB, allowlisted MIME types).`);
} else {
  console.log(`Bucket "${bucket}" created (private, ${maxMb} MB, allowlisted MIME types).`);
}
