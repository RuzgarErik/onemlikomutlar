# FFMpeg

## Video Hakkında Bilgi Alma
ffmpeg -i video.mp4

## Video Formatı Dönüştürme
ffmpeg in.mp4 out.mkv 

"-qscale 0" komutu kaliteyi korur

## Videoyu Sese Dönüştürme 
ffmpeg -i input.mp4 -vn output.mp3

-ab - Indicates the audio bitrate.

## Video ses seviyesi ayarlama

ffmpeg -i input.mp3 -af 'volume=1.5' output.mp3

## Video çözünürlük değiştirme

ffmpeg -i input.mp4 -filter:v scale=1280:720 -c:a copy output.mp4

## Video sıkıştırma

ffmpeg -i input.mp4 -vf scale=1280:-1 -c:v libx264 -preset veryslow -crf 24 output.mp4

crf değeri sıkıştırmayı ayarlar

## Ses sıkıştırma

ffmpeg -i input.mp3 -ab 128 output.mp3
    96kbps
    112kbps
    128kbps
    160kbps
    192kbps
    256kbps
    320kbps

## Ses Silme

ffmpeg -i input.mp4 -an output.mp4

-an Sesi kaldırır

## Bütün Frameleri Alma

ffmpeg -i input.mp4 -r 1 -f image2 image-%2d.png

## Kırpma

ffmpeg -i input.mp4 -filter:v "crop=w:h:x:y" output.mp4

## Kesme

ffmpeg -i audio.mp3 -ss 00:01:54 -to 00:06:53 -c copy output.mp3

## Video Hızlandırma Yavaşlatma

ffmpeg -i input.mp4 -vf "setpts=0.5*PTS" output.mp4

1 üstü değerler yavaşlatır

## Ses Hızlandırma Yavaşlatma

ffmpeg -i input.mp4 -filter:a "atempo=2.0" -vn output.mp4

atempo 0.5-2.5 arası
