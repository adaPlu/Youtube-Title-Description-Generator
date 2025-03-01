# Made By Ada Pluguez
# YoutubeTitlerCLI-Uses openai api to generate search optimized youtube titles, descriptions,and TAGS.
# Then replaces the channels titles etc. with the newly generated ones.
# 03/01/24
import os
import requests
import time
import logging
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow

# Configure logging
logging.basicConfig(filename='Errors.log', filemode='a', format='%(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# Use environment variables for sensitive information
scopes = ["https://www.googleapis.com/auth/youtube.force-ssl"]
api_key = os.getenv('OPENAI_API_KEY')
client_secrets_file = os.getenv('CLIENT_SECRETS_FILE')

def get_authenticated_service():
    flow = InstalledAppFlow.from_client_secrets_file(client_secrets_file, scopes)
    credentials = flow.run_local_server()
    return build("youtube", "v3", credentials=credentials)

def fetch_upload_playlist_id(youtube):
    channels_response = youtube.channels().list(part="contentDetails", mine=True).execute()
    return channels_response['items'][0]['contentDetails']['relatedPlaylists']['uploads']

def generate_youtube_content(video_title, video_description, api_key):
    service_url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"}
    prompt = f"Generate a search optimized YouTube video title, a brief description, and suggest some appropriate tags based on the following title and description:\n\nTitle: {video_title}\nDescription: {video_description}"
    data = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant designed to generate or optimize creative YouTube content, titles, descriptions, and tags."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7
    }
    for attempt in range(5):
        response = requests.post(service_url, headers=headers, json=data)
        if response.status_code == 200:
            content = response.json()
            choices = content.get("choices", [])
            if choices:
                generated_text = choices[0]['message']['content'].strip()
                return parse_generated_content(generated_text)
            else:
                logging.info(f"No generated content available for video title: {video_title}")
            break
        elif response.status_code == 429:
            logging.warning(f"Rate limit exceeded on attempt {attempt + 1} for video title: {video_title}. Retrying...")
            time.sleep(1 * (2 ** attempt))
        else:
            logging.error(f"Failed to generate content due to an API error. Status Code: {response.status_code}, Response: {response.text}")
            break
    return video_title, video_description, []

def parse_generated_content(generated_text):
    new_title, new_description, new_tags = None, None, []
    if "Title:" in generated_text and "Description:" in generated_text:
        title_part = generated_text.split("Description:")[0].strip()
        new_title = title_part.replace("Title:", "").strip()
        desc_and_tags_part = generated_text.split("Description:")[1].strip()
        if "Tags:" in desc_and_tags_part:
            new_description, tags_part = desc_and_tags_part.split("Tags:")
            new_tags = [tag.strip() for tag in tags_part.split(",") if tag.strip()]
        else:
            new_description = desc_and_tags_part
        new_description = new_description.strip()
    if not new_title or not new_description:
        logging.error("Failed to parse the title or description from the generated content.")
    return new_title, new_description, new_tags

def update_videos(youtube, uploads_playlist_id, api_key):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"
    video_counter, next_page_token = 0, None
    while next_page_token is not None or video_counter == 0:
        playlist_items_response = youtube.playlistItems().list(
            part="snippet",
            playlistId=uploads_playlist_id,
            maxResults=50,
            pageToken=next_page_token
        ).execute()
        for item in playlist_items_response.get('items', []):
            video_counter += 1
            if video_counter > 911 and video_counter < 999:
                video_id = item['snippet']['resourceId']['videoId']
                video_title = item['snippet']['title']
                video_description = item['snippet']['description']
                new_title, new_description, new_tags = generate_youtube_content(video_title, video_description, api_key)
                print(video_counter)
                if new_title and new_description:  # Ensure we have new content before updating
                    update_video(youtube, video_id, new_title, new_description, new_tags)
            elif video_counter >= 999:
                break
        next_page_token = playlist_items_response.get('nextPageToken', None)

def update_video(youtube, video_id, new_title, new_description, new_tags):
    update_request_body = {
        "id": video_id,
        "snippet": {
            "title": new_title,
            "description": new_description,
            "tags": new_tags,
            "categoryId": "22"
        }
    }
    try:
        update_request = youtube.videos().update(part="snippet", body=update_request_body)
        update_request.execute()
        logging.info(f"Video {video_id} updated successfully.")
    except Exception as error:
        logging.error(f"An error occurred: {error}")

def main():
    youtube = get_authenticated_service()
    uploads_playlist_id = fetch_upload_playlist_id(youtube)
    update_videos(youtube, uploads_playlist_id, api_key)

if __name__ == "__main__":
    main()
