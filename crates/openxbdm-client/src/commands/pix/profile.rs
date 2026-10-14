//! Capture profile selection.
//!
//! XBMovie embeds ten stock Windows Media Profile XML blobs for different
//! resolution/bitrate/audio combinations, plus we ship one custom
//! [`CaptureProfile::HighBitrate1080p30`] preset tuned for better motion
//! handling than the stock profiles.

/// Resolution label attached to a capture profile. Drives which stock
/// XML blob we select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// 136p (242x136 in practice; low-res debug helper).
    R136p,
    /// 180p widescreen downscale.
    R180p,
    /// 224p widescreen downscale.
    R224p,
    /// 360p widescreen downscale.
    R360p,
    /// 720p (1280x720).
    R720p,
    /// 720p stereoscopic 3D (left eye).
    R720pLeftEye,
    /// 720p stereoscopic 3D (right eye).
    R720pRightEye,
    /// 1080p (1920x1080).
    R1080p,
    /// 1470p stereoscopic 3D side-by-side.
    R1470p3D,
}

/// Frame rate of the on-device HDMI output to match against the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdmiFrameRate {
    Fps30,
    Fps60,
}

/// Ready-made capture profile. Variants with names like
/// `Profile_F2_720p_8Mbps` correspond exactly to the stock XML blobs
/// XBMovie ships; `HighBitrate1080p30` is our own tuned profile.
#[derive(Debug, Clone)]
pub enum CaptureProfile {
    /// F5: 136p video at 42 Kbps, 16 Kbps mono audio.
    ProfileF5_136p,
    /// F4: 180p video at 542 Kbps, 64 Kbps stereo audio.
    ProfileF4_180p,
    /// G1: 224p video at 1.4 Mbps, 96 Kbps stereo audio.
    ProfileG1_224p,
    /// F3: 360p video at 1.4 Mbps, 96 Kbps stereo audio.
    ProfileF3_360p,
    /// F2: 720p30 at 8 Mbps, 192 Kbps stereo audio.
    ProfileF2_720p30,
    /// F6: 720p60 at 15 Mbps, 384 Kbps 5.1 audio.
    ProfileF6_720p60,
    /// F9: 720p3D left eye at 8 Mbps, 384 Kbps 5.1 audio.
    ProfileF9_720p3DLeft,
    /// F10: 720p3D right eye at 8 Mbps, 384 Kbps 5.1 audio.
    ProfileF10_720p3DRight,
    /// X1: 1080p at 15 Mbps, 384 Kbps 5.1 audio.
    ProfileX1_1080p,
    /// F8: 1470p3D side-by-side at 15 Mbps, 384 Kbps 5.1 audio.
    ProfileF8_1470p3D,
    /// Our high-bitrate custom profile: 1080p30 at 25 Mbps CBR, WMV3
    /// Advanced Profile, 2-second GOP, 384 Kbps 5.1 audio.
    HighBitrate1080p30,
    /// A completely user-supplied profile XML. Must be a valid Windows
    /// Media Profile document.
    Custom { xml: String },
}

impl CaptureProfile {
    /// Resolution this profile targets.
    pub fn resolution(&self) -> Resolution {
        match self {
            CaptureProfile::ProfileF5_136p => Resolution::R136p,
            CaptureProfile::ProfileF4_180p => Resolution::R180p,
            CaptureProfile::ProfileG1_224p => Resolution::R224p,
            CaptureProfile::ProfileF3_360p => Resolution::R360p,
            CaptureProfile::ProfileF2_720p30 => Resolution::R720p,
            CaptureProfile::ProfileF6_720p60 => Resolution::R720p,
            CaptureProfile::ProfileF9_720p3DLeft => Resolution::R720pLeftEye,
            CaptureProfile::ProfileF10_720p3DRight => Resolution::R720pRightEye,
            CaptureProfile::ProfileX1_1080p => Resolution::R1080p,
            CaptureProfile::ProfileF8_1470p3D => Resolution::R1470p3D,
            CaptureProfile::HighBitrate1080p30 => Resolution::R1080p,
            CaptureProfile::Custom { .. } => Resolution::R1080p,
        }
    }

    /// Frame rate this profile targets.
    pub fn frame_rate(&self) -> HdmiFrameRate {
        match self {
            CaptureProfile::ProfileF6_720p60 => HdmiFrameRate::Fps60,
            _ => HdmiFrameRate::Fps30,
        }
    }

    /// Profile display name (matches the `name="..."` attribute in the
    /// stock XML blobs).
    pub fn label(&self) -> &'static str {
        match self {
            CaptureProfile::ProfileF5_136p => "XBMovie_F5_V90_42KVideo136p_16KAudioMono",
            CaptureProfile::ProfileF4_180p => "XBMovie_F4_V90_542KVideo180p_64KAudioStereo",
            CaptureProfile::ProfileG1_224p => "XBMovie_G1_V90_1395KVideo224p_96KAudioStereo",
            CaptureProfile::ProfileF3_360p => "XBMovie_F3_V90_1395KVideo360p_96KAudioStereo",
            CaptureProfile::ProfileF2_720p30 => "XBMovie_F2_V90_8MVideo720p_192KAudioStereo",
            CaptureProfile::ProfileF6_720p60 => "XBMovie_F6_V90_15MVideo720p60_384KAudio5.1",
            CaptureProfile::ProfileF9_720p3DLeft => {
                "XBMovie_F9_V90_8MVideo720p3DLeftEye_384KAudio5.1"
            }
            CaptureProfile::ProfileF10_720p3DRight => {
                "XBMovie_F10_V90_8MVideo720p3DRightEye_384KAudio5.1"
            }
            CaptureProfile::ProfileX1_1080p => "XBMovie_X1_V90_15MVideo1080p_384KAudio5.1",
            CaptureProfile::ProfileF8_1470p3D => "XBMovie_F8_V90_15MVideo1470p3D_384KAudio5.1",
            CaptureProfile::HighBitrate1080p30 => "Openxbdm_HighBitrate_1080p30_25Mbps",
            CaptureProfile::Custom { .. } => "Openxbdm_Custom_Profile",
        }
    }

    /// XML profile body pushed to the console for this preset.
    pub fn xml(&self) -> &str {
        match self {
            CaptureProfile::Custom { xml } => xml.as_str(),
            CaptureProfile::HighBitrate1080p30 => HIGH_BITRATE_1080P30_XML,
            CaptureProfile::ProfileX1_1080p => STOCK_X1_1080P_XML,
            CaptureProfile::ProfileF6_720p60 => STOCK_F6_720P60_XML,
            CaptureProfile::ProfileF2_720p30 => STOCK_F2_720P30_XML,
            CaptureProfile::ProfileF8_1470p3D => STOCK_F8_1470P3D_XML,
            CaptureProfile::ProfileF9_720p3DLeft => STOCK_F9_720P3D_LEFT_XML,
            CaptureProfile::ProfileF10_720p3DRight => STOCK_F10_720P3D_RIGHT_XML,
            CaptureProfile::ProfileF3_360p => STOCK_F3_360P_XML,
            CaptureProfile::ProfileG1_224p => STOCK_G1_224P_XML,
            CaptureProfile::ProfileF4_180p => STOCK_F4_180P_XML,
            CaptureProfile::ProfileF5_136p => STOCK_F5_136P_XML,
        }
    }
}

// The ten Windows Media Profile XML strings xbmovie ships in its `.rdata`.
// Wire format is a `<profile version="589824">` document describing the
// audio + video stream configs; the console's PIX extension consumes it
// verbatim.

const STOCK_X1_1080P_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_X1_V90_15MVideo1080p_384KAudio5.1" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="15000000" bufferwindow="8000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="97"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="15000000" dwbiterrorrate="0" avgtimeperframe="166833">
                <rcsource left="0" top="0" right="1920" bottom="1080"/>
                <rctarget left="0" top="0" right="1920" bottom="1080"/>
                <bitmapinfoheader biwidth="1920" biheight="1080" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0" bixpelspermeter="0" biypelspermeter="0" biclrused="0" biclrimportant="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="384000" bufferwindow="8000" reliabletransport="0" decodercomplexity="" rfc1766langid="en-us">
        <wmmediatype subtype="{00000162-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="354" nChannels="6" nSamplesPerSec="48000" nAvgBytesPerSec="48000" nBlockAlign="8192" wBitsPerSample="16" codecdata="8800000000F01F00C0AA00004400000000E0000000"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_F6_720P60_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_F6_V90_15MVideo720p60_384KAudio5.1" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="15000000" bufferwindow="8000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="97"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="15000000" dwbiterrorrate="0" avgtimeperframe="166833">
                <rcsource left="0" top="0" right="1280" bottom="720"/>
                <rctarget left="0" top="0" right="1280" bottom="720"/>
                <bitmapinfoheader biwidth="1280" biheight="720" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0" bixpelspermeter="0" biypelspermeter="0" biclrused="0" biclrimportant="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="384000" bufferwindow="8000" reliabletransport="0" decodercomplexity="" rfc1766langid="en-us">
        <wmmediatype subtype="{00000162-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="354" nChannels="6" nSamplesPerSec="48000" nAvgBytesPerSec="48000" nBlockAlign="8192" wBitsPerSample="16" codecdata="8800000000F01F00C0AA00004400000000E0000000"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_F2_720P30_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_F2_V90_8MVideo720p_192KAudioStereo" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="8000000" bufferwindow="8000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="97"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="8000000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="1280" bottom="720"/>
                <rctarget left="0" top="0" right="1280" bottom="720"/>
                <bitmapinfoheader biwidth="1280" biheight="720" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0" bixpelspermeter="0" biypelspermeter="0" biclrused="0" biclrimportant="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="192000" bufferwindow="8000" reliabletransport="0" decodercomplexity="" rfc1766langid="en-us">
        <wmmediatype subtype="{00000161-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="353" nChannels="2" nSamplesPerSec="48000" nAvgBytesPerSec="24000" nBlockAlign="10240" wBitsPerSample="16" codecdata="008800000FF803FF010000"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_F3_360P_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_F3_V90_1395KVideo360p_96KAudioStereo" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="1395000" bufferwindow="5000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="85"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="1395000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="640" bottom="360"/>
                <rctarget left="0" top="0" right="640" bottom="360"/>
                <bitmapinfoheader biwidth="640" biheight="360" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="96000" bufferwindow="5000" reliabletransport="0">
        <wmmediatype subtype="{00000161-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="353" nChannels="2" nSamplesPerSec="44100" nAvgBytesPerSec="12000" nBlockAlign="4459" wBitsPerSample="16"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_G1_224P_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_G1_V90_1395KVideo224p_96KAudioStereo" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="1395000" bufferwindow="5000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="85"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="1395000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="400" bottom="224"/>
                <rctarget left="0" top="0" right="400" bottom="224"/>
                <bitmapinfoheader biwidth="400" biheight="224" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="96000" bufferwindow="5000" reliabletransport="0">
        <wmmediatype subtype="{00000161-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="353" nChannels="2" nSamplesPerSec="44100" nAvgBytesPerSec="12000" nBlockAlign="4459" wBitsPerSample="16"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_F4_180P_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_F4_V90_542KVideo180p_64KAudioStereo" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="542000" bufferwindow="6000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="60"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="542000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="320" bottom="180"/>
                <rctarget left="0" top="0" right="320" bottom="180"/>
                <bitmapinfoheader biwidth="320" biheight="180" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="64008" bufferwindow="6000" reliabletransport="0">
        <wmmediatype subtype="{00000162-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="354" nChannels="2" nSamplesPerSec="44100" nAvgBytesPerSec="8001" nBlockAlign="2976" wBitsPerSample="16"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_F5_136P_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_F5_V90_42KVideo136p_16KAudioMono" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="42000" bufferwindow="6000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="50"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="42000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="240" bottom="136"/>
                <rctarget left="0" top="0" right="240" bottom="136"/>
                <bitmapinfoheader biwidth="240" biheight="136" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="16000" bufferwindow="6000" reliabletransport="0">
        <wmmediatype subtype="{00000162-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="354" nChannels="1" nSamplesPerSec="32000" nAvgBytesPerSec="2000" nBlockAlign="714" wBitsPerSample="16"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_F8_1470P3D_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_F8_V90_15MVideo1470p3D_384KAudio5.1" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="15000000" bufferwindow="8000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="97"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="15000000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="2560" bottom="1470"/>
                <rctarget left="0" top="0" right="2560" bottom="1470"/>
                <bitmapinfoheader biwidth="2560" biheight="1470" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="384000" bufferwindow="8000" reliabletransport="0">
        <wmmediatype subtype="{00000162-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="354" nChannels="6" nSamplesPerSec="48000" nAvgBytesPerSec="48000" nBlockAlign="8192" wBitsPerSample="16"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_F9_720P3D_LEFT_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_F9_V90_8MVideo720p3DLeftEye_384KAudio5.1" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="8000000" bufferwindow="8000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="93"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="8000000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="1280" bottom="720"/>
                <rctarget left="0" top="0" right="1280" bottom="720"/>
                <bitmapinfoheader biwidth="1280" biheight="720" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="384000" bufferwindow="8000" reliabletransport="0">
        <wmmediatype subtype="{00000162-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="354" nChannels="6" nSamplesPerSec="48000" nAvgBytesPerSec="48000" nBlockAlign="8192" wBitsPerSample="16"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

const STOCK_F10_720P3D_RIGHT_XML: &str = r#"<profile version="589824" storageformat="1" name="XBMovie_F10_V90_8MVideo720p3DRightEye_384KAudio5.1" description="Streams: 1 audio 1 video">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="8000000" bufferwindow="8000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="80000000" quality="93"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="8000000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="1280" bottom="720"/>
                <rctarget left="0" top="0" right="1280" bottom="720"/>
                <bitmapinfoheader biwidth="1280" biheight="720" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="384000" bufferwindow="8000" reliabletransport="0">
        <wmmediatype subtype="{00000162-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="354" nChannels="6" nSamplesPerSec="48000" nAvgBytesPerSec="48000" nBlockAlign="8192" wBitsPerSample="16"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

// Our custom high-bitrate profile, tuned for clean motion:
//
// - 25 Mbps CBR video to avoid the rate-control starvation that makes
//   stock 15 Mbps profiles smear on fast scenes.
// - `maxkeyframespacing="20000000"` = 2 s keyframe interval (vs. 8 s in
//   the stocks), so seeking and segment stitching produce fewer seam
//   artifacts.
// - `bufferwindow="2000"` = 2 s VBV buffer, keeps the encoder from
//   producing long latency bursts the console struggles with.
// - WMV3 Advanced Profile (`decodercomplexity="AP"`) and H.264-adjacent
//   quality 100.
// - 5.1 audio at 384 Kbps (WMA Pro), matched to the HDMI output.
const HIGH_BITRATE_1080P30_XML: &str = r#"<profile version="589824" storageformat="1" name="Openxbdm_HighBitrate_1080p30_25Mbps" description="Custom 1080p30 25Mbps CBR WMV3-AP + 5.1 audio">
    <streamconfig majortype="{73646976-0000-0010-8000-00AA00389B71}" streamnumber="2" streamname="Video2" inputname="Video" bitrate="25000000" bufferwindow="2000" reliabletransport="0" decodercomplexity="AP" rfc1766langid="en-us">
        <videomediaprops maxkeyframespacing="20000000" quality="100"/>
        <wmmediatype subtype="{33564D57-0000-0010-8000-00AA00389B71}" bfixedsizesamples="0" btemporalcompression="1" lsamplesize="0">
            <videoinfoheader dwbitrate="25000000" dwbiterrorrate="0" avgtimeperframe="333667">
                <rcsource left="0" top="0" right="1920" bottom="1080"/>
                <rctarget left="0" top="0" right="1920" bottom="1080"/>
                <bitmapinfoheader biwidth="1920" biheight="1080" biplanes="1" bibitcount="24" bicompression="WMV3" bisizeimage="0" bixpelspermeter="0" biypelspermeter="0" biclrused="0" biclrimportant="0"/>
            </videoinfoheader>
        </wmmediatype>
    </streamconfig>
    <streamconfig majortype="{73647561-0000-0010-8000-00AA00389B71}" streamnumber="1" streamname="Audio1" inputname="Audio" bitrate="384000" bufferwindow="2000" reliabletransport="0" decodercomplexity="" rfc1766langid="en-us">
        <wmmediatype subtype="{00000162-0000-0010-8000-00AA00389B71}" bfixedsizesamples="1" btemporalcompression="0" lsamplesize="0">
            <waveformatex wFormatTag="354" nChannels="6" nSamplesPerSec="48000" nAvgBytesPerSec="48000" nBlockAlign="8192" wBitsPerSample="16" codecdata="8800000000F01F00C0AA00004400000000E0000000"/>
        </wmmediatype>
    </streamconfig>
</profile>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stock_preset_has_a_nonempty_xml() {
        let presets = [
            CaptureProfile::ProfileF5_136p,
            CaptureProfile::ProfileF4_180p,
            CaptureProfile::ProfileG1_224p,
            CaptureProfile::ProfileF3_360p,
            CaptureProfile::ProfileF2_720p30,
            CaptureProfile::ProfileF6_720p60,
            CaptureProfile::ProfileF9_720p3DLeft,
            CaptureProfile::ProfileF10_720p3DRight,
            CaptureProfile::ProfileX1_1080p,
            CaptureProfile::ProfileF8_1470p3D,
            CaptureProfile::HighBitrate1080p30,
        ];
        for profile in &presets {
            let xml = profile.xml();
            assert!(xml.starts_with("<profile"), "{}", profile.label());
            assert!(xml.ends_with("</profile>"), "{}", profile.label());
            assert!(
                xml.contains(profile.label()),
                "XML body missing profile name {}",
                profile.label()
            );
        }
    }

    #[test]
    fn high_bitrate_profile_overrides_stock_defaults() {
        let xml = CaptureProfile::HighBitrate1080p30.xml();
        assert!(xml.contains("bitrate=\"25000000\""));
        assert!(xml.contains("maxkeyframespacing=\"20000000\""));
        assert!(xml.contains("bufferwindow=\"2000\""));
    }
}
