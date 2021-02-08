use usiem::events::webproxy::{WebProxyRuleCategory};
// https://www.sonicwall.com/support/knowledge-base/content-filtering-service-cfs-4-0-overview/170505704497427/
pub fn web_category(cat : &str) -> WebProxyRuleCategory {
    match cat {
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
        "Not Rated" => WebProxyRuleCategory::Uncategorized,
        _ => WebProxyRuleCategory::Others(cat.to_string())
    }
}

pub fn web_code_category(cat : u32) -> WebProxyRuleCategory {
    match cat {
        1 => WebProxyRuleCategory::Violence,
        2 => WebProxyRuleCategory::IntimateApparel,
        3 => WebProxyRuleCategory::Nudity,
        4 => WebProxyRuleCategory::Pornography,
        5 => WebProxyRuleCategory::Weapons,
        6 => WebProxyRuleCategory::MatureContent,
        7 => WebProxyRuleCategory::Religion,
        8 => WebProxyRuleCategory::Marijuana,
        9 => WebProxyRuleCategory::QuestionableLegality,
        10 => WebProxyRuleCategory::SexEducation,
        11 => WebProxyRuleCategory::Gambling,
        12 => WebProxyRuleCategory::Alcohol,
        13 => WebProxyRuleCategory::OnlineChat,
        14 => WebProxyRuleCategory::ArtCulture,
        15 => WebProxyRuleCategory::BusinessApplications,
        16 => WebProxyRuleCategory::Abortion,
        17 => WebProxyRuleCategory::Education,
        //18?
        19 => WebProxyRuleCategory::ArtCulture,        
        20 => WebProxyRuleCategory::Finance,
        21 => WebProxyRuleCategory::Trading,
        22 => WebProxyRuleCategory::Games,
        23 => WebProxyRuleCategory::Government,
        24 => WebProxyRuleCategory::Military,
        25 => WebProxyRuleCategory::PoliticalAdvocacy,
        26 => WebProxyRuleCategory::Health,
        27 => WebProxyRuleCategory::Technology,
        28 => WebProxyRuleCategory::ProxyAvoidance,
        29 => WebProxyRuleCategory::SearchEngines,
        30 => WebProxyRuleCategory::Email,
        31 => WebProxyRuleCategory::Informational,
        32  => WebProxyRuleCategory::JobSearch,
        33 => WebProxyRuleCategory::News,
        34 => WebProxyRuleCategory::PersonalsDating,
        35 => WebProxyRuleCategory::News,
        36 => WebProxyRuleCategory::Reference,
        37 => WebProxyRuleCategory::Religion,
        38 => WebProxyRuleCategory::Shopping,
        39 => WebProxyRuleCategory::Auctions,
        40 => WebProxyRuleCategory::RealEstate,
        41 => WebProxyRuleCategory::DailyLiving,
        //42??
        43 => WebProxyRuleCategory::Restaurants,
        44 => WebProxyRuleCategory::Sports,
        45 => WebProxyRuleCategory::Travel,
        46 => WebProxyRuleCategory::Vehicles,
        47 => WebProxyRuleCategory::HumorJokes,
        48 => WebProxyRuleCategory::MediaSharing,
        49 => WebProxyRuleCategory::PotentiallyUnwantedSoftware,
        50 => WebProxyRuleCategory::ProxyAvoidance,
        //??
        53 => WebProxyRuleCategory::ForKids,
        54 => WebProxyRuleCategory::WebAds,
        55 => WebProxyRuleCategory::WebHosting,
        56 => WebProxyRuleCategory::Uncategorized,
        57 => WebProxyRuleCategory::InformationSecurity,
        58 => WebProxyRuleCategory::SocialNetworking,
        59 => WebProxyRuleCategory::MaliciousSources,
        60 => WebProxyRuleCategory::QuestionableLegality,
        64 => WebProxyRuleCategory::Uncategorized,
        _ => WebProxyRuleCategory::Others(cat.to_string())
    }
}