use usiem::events::webproxy::{WebProxyRuleCategory};
use phf::phf_map;
use phf;
// https://www.sonicwall.com/support/knowledge-base/content-filtering-service-cfs-4-0-overview/170505704497427/

static KEYWORDS: phf::Map<&'static str, WebProxyRuleCategory> = phf_map! {
    "Violence/Hate/Racism" => WebProxyRuleCategory::Violence,
    "Intimate Apparel/SwimSuit" => WebProxyRuleCategory::IntimateApparel,
    "Nudism" => WebProxyRuleCategory::Nudity,
    "Pornography" => WebProxyRuleCategory::Pornography,
    "Weapons" => WebProxyRuleCategory::Weapons,
    "Adult/Mature Content" => WebProxyRuleCategory::MatureContent,
    "Cult/Occult" => WebProxyRuleCategory::Religion,
    "Drugs/Illegal Drugs" => WebProxyRuleCategory::Marijuana,
    "Illegal Skills/Questionable Skills" => WebProxyRuleCategory::QuestionableLegality,
    "Sex Education" => WebProxyRuleCategory::SexEducation,
    "Gambling" => WebProxyRuleCategory::Gambling,
    "Alcohol/Tobacco" => WebProxyRuleCategory::Alcohol,
    "Chat/Instant Messaging (IM)" => WebProxyRuleCategory::OnlineChat,
    "Arts/Entertainment" => WebProxyRuleCategory::ArtCulture,
    "Business and Economy" => WebProxyRuleCategory::BusinessApplications,
    "Abortion/Advocacy Groups" => WebProxyRuleCategory::Abortion,
    "Education" => WebProxyRuleCategory::Education,
    "Cultural Institutions" => WebProxyRuleCategory::ArtCulture,        
    "Online Banking" => WebProxyRuleCategory::Finance,
    "Online Brokerage and Trading" => WebProxyRuleCategory::Trading,
    "Games" => WebProxyRuleCategory::Games,
    "Government" => WebProxyRuleCategory::Government,
    "Military" => WebProxyRuleCategory::Military,
    "Political/Advocacy Groups" => WebProxyRuleCategory::PoliticalAdvocacy,
    "Health" => WebProxyRuleCategory::Health,
    "Information Technology/Computers" => WebProxyRuleCategory::Technology,
    "Hacking/Proxy Avoidance Systems" => WebProxyRuleCategory::ProxyAvoidance,
    "Search Engines and Portals" => WebProxyRuleCategory::SearchEngines,
    "E-Mail" => WebProxyRuleCategory::Email,
    "Web Communications" => WebProxyRuleCategory::Informational,
    "Job Search"  => WebProxyRuleCategory::JobSearch,
    "News and Media" => WebProxyRuleCategory::News,
    "Personals and Dating" => WebProxyRuleCategory::PersonalsDating,
    "Usenet News Groups" => WebProxyRuleCategory::News,
    "Reference" => WebProxyRuleCategory::Reference,
    "Religion" => WebProxyRuleCategory::Religion,
    "Shopping" => WebProxyRuleCategory::Shopping,
    "Internet Auctions" => WebProxyRuleCategory::Auctions,
    "Real Estate" => WebProxyRuleCategory::RealEstate,
    "Society and Lifestyle" => WebProxyRuleCategory::DailyLiving,
    "Restaurants and Dining" => WebProxyRuleCategory::Restaurants,
    "Sports/Recreation" => WebProxyRuleCategory::Sports,
    "Travel" => WebProxyRuleCategory::Travel,
    "Vehicles" => WebProxyRuleCategory::Vehicles,
    "Humor/Jokes" => WebProxyRuleCategory::HumorJokes,
    "Multimedia" => WebProxyRuleCategory::MediaSharing,
    "Freeware/Software Downloads" => WebProxyRuleCategory::PotentiallyUnwantedSoftware,
    "Pay to Surf Sites" => WebProxyRuleCategory::ProxyAvoidance,
    "Kid Friendly" => WebProxyRuleCategory::ForKids,
    "Advertisement" => WebProxyRuleCategory::WebAds,
    "Web Hosting" => WebProxyRuleCategory::WebHosting,
    "Other" => WebProxyRuleCategory::Uncategorized,
    "Internet Watch Foundation CAIC" => WebProxyRuleCategory::InformationSecurity,
    "Social Networking" => WebProxyRuleCategory::SocialNetworking,
    "Malware" => WebProxyRuleCategory::MaliciousSources,
    "Radicalization and Extremism" => WebProxyRuleCategory::QuestionableLegality,
    "Not Rated" => WebProxyRuleCategory::Uncategorized
};

static CODES: phf::Map<u32, WebProxyRuleCategory> = phf_map! {
    1u32 => WebProxyRuleCategory::Violence,
    2u32 => WebProxyRuleCategory::IntimateApparel,
    3u32 => WebProxyRuleCategory::Nudity,
    4u32 => WebProxyRuleCategory::Pornography,
    5u32 => WebProxyRuleCategory::Weapons,
    6u32 => WebProxyRuleCategory::MatureContent,
    7u32 => WebProxyRuleCategory::Religion,
    8u32 => WebProxyRuleCategory::Marijuana,
    9u32 => WebProxyRuleCategory::QuestionableLegality,
    10u32 => WebProxyRuleCategory::SexEducation,
    11u32 => WebProxyRuleCategory::Gambling,
    12u32 => WebProxyRuleCategory::Alcohol,
    13u32 => WebProxyRuleCategory::OnlineChat,
    14u32 => WebProxyRuleCategory::ArtCulture,
    15u32 => WebProxyRuleCategory::BusinessApplications,
    16u32 => WebProxyRuleCategory::Abortion,
    17u32 => WebProxyRuleCategory::Education,
    //18?
    19u32 => WebProxyRuleCategory::ArtCulture,        
    20u32 => WebProxyRuleCategory::Finance,
    21u32 => WebProxyRuleCategory::Trading,
    22u32 => WebProxyRuleCategory::Games,
    23u32 => WebProxyRuleCategory::Government,
    24u32 => WebProxyRuleCategory::Military,
    25u32 => WebProxyRuleCategory::PoliticalAdvocacy,
    26u32 => WebProxyRuleCategory::Health,
    27u32 => WebProxyRuleCategory::Technology,
    28u32 => WebProxyRuleCategory::ProxyAvoidance,
    29u32 => WebProxyRuleCategory::SearchEngines,
    30u32 => WebProxyRuleCategory::Email,
    31u32 => WebProxyRuleCategory::Informational,
    32u32 => WebProxyRuleCategory::JobSearch,
    33u32 => WebProxyRuleCategory::News,
    34u32 => WebProxyRuleCategory::PersonalsDating,
    35u32 => WebProxyRuleCategory::News,
    36u32 => WebProxyRuleCategory::Reference,
    37u32 => WebProxyRuleCategory::Religion,
    38u32 => WebProxyRuleCategory::Shopping,
    39u32 => WebProxyRuleCategory::Auctions,
    40u32 => WebProxyRuleCategory::RealEstate,
    41u32 => WebProxyRuleCategory::DailyLiving,
    //42??
    43u32 => WebProxyRuleCategory::Restaurants,
    44u32 => WebProxyRuleCategory::Sports,
    45u32 => WebProxyRuleCategory::Travel,
    46u32 => WebProxyRuleCategory::Vehicles,
    47u32 => WebProxyRuleCategory::HumorJokes,
    48u32 => WebProxyRuleCategory::MediaSharing,
    49u32 => WebProxyRuleCategory::PotentiallyUnwantedSoftware,
    50u32 => WebProxyRuleCategory::ProxyAvoidance,
    //??
    53u32 => WebProxyRuleCategory::ForKids,
    54u32 => WebProxyRuleCategory::WebAds,
    55u32 => WebProxyRuleCategory::WebHosting,
    56u32 => WebProxyRuleCategory::Uncategorized,
    57u32 => WebProxyRuleCategory::InformationSecurity,
    58u32 => WebProxyRuleCategory::SocialNetworking,
    59u32 => WebProxyRuleCategory::MaliciousSources,
    60u32 => WebProxyRuleCategory::QuestionableLegality,
    64u32 => WebProxyRuleCategory::Uncategorized,
};

pub fn web_category(cat : &str) -> WebProxyRuleCategory {
    match KEYWORDS.get(cat) {
        Some(v) => {
            v.clone()
        },
        None => {
            WebProxyRuleCategory::Others(cat.to_string())
        }
    }
}

pub fn web_code_category(cat : u32) -> WebProxyRuleCategory {
    match CODES.get(&cat) {
        Some(v) => {
            v.clone()
        },
        None => {
            WebProxyRuleCategory::Others(cat.to_string())
        }
    }
}