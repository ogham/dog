macro_rules! u16_enum {
    {
        $(#[$attr:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vattr:meta])*
                $variant:ident = $lit:literal,)+
        }
    } => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq)]
        #[repr(u16)]
        $vis enum $name {
            $(
                $(#[$vattr])*
                $variant = $lit,)+
        }
        impl core::convert::TryFrom<u16> for $name {
            type Error = std::io::Error;

            fn try_from(int: u16) -> Result<Self, Self::Error> {
                match int {
                    $($lit => Ok(Self::$variant),)+
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("invalid value for {}: {:04x}", stringify!($name), int)
                        )
                    )
                }
            }
        }
    };
    {
        $(#[$attr:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vattr:meta])*
                $variant:ident = $lit:literal,)+
            $(
                @unknown
                $(#[$uattr:meta])*
                $unknown:ident (u16),
                $(
                    $(#[$vattr2:meta])*
                    $variant2:ident = $lit2:literal,)*
            )?
        }
    } => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq)]
        #[repr(u16)]
        $vis enum $name {
            $(
                $(#[$vattr])*
                $variant = $lit,)+
            $(
                $(#[$uattr])*
                $unknown(u16),
                $(
                    $(#[$vattr2])*
                    $variant2 = $lit2,)*
            )?
        }
        impl From<u16> for $name {
            fn from(int: u16) -> Self {
                match int {
                    $($lit => Self::$variant,)+
                    $(
                        $($lit2 => Self::$variant2,)*
                        _ => Self::$unknown(int),
                    )?
                }
            }
        }
    };
}
