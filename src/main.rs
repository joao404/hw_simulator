#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use core::mem::MaybeUninit;

use defmt::*;
use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Ipv4Address, Ipv4Cidr, StackResources};
use embassy_stm32::eth::generic_smi::GenericSMI;
use embassy_stm32::eth::{Ethernet, PacketQueue};
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::peripherals::ETH;
use embassy_stm32::rng::Rng;
use embassy_stm32::SharedData;
use embassy_stm32::{bind_interrupts, eth, peripherals, rng};
use embassy_time::{Duration, Timer};
use embedded_io_async::Write;
use heapless::Vec;
use rand_core::RngCore;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use picoserve::{make_static, routing::get, AppBuilder, AppRouter};

use stm32_metapac::ETH as ETH_pac;

#[unsafe(link_section = ".ram_d3.shared_data")]
static SHARED_DATA: MaybeUninit<SharedData> = MaybeUninit::uninit();

#[global_allocator]
static ALLOCATOR: emballoc::Allocator<4096> = emballoc::Allocator::new();

extern crate alloc;

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

type Device = Ethernet<'static, ETH, GenericSMI>;

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, Device>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn blink(mut led: Output<'static>, interval_ms: u64) {
    loop {
        led.set_high();
        Timer::after_millis(interval_ms).await;
        led.set_low();
        Timer::after_millis(interval_ms).await;
    }
}

#[embassy_executor::task]
async fn udp_handler(stack: embassy_net::Stack<'static>) {
    // Then we can use it!
    let mut rx_buffer = [0; 1024];
    let mut tx_buffer = [0; 1024];
    let mut rx_meta = [PacketMetadata::EMPTY; 16];
    let mut tx_meta = [PacketMetadata::EMPTY; 16];
    let mut buf = [0; 1024];

    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    socket
        .bind(embassy_net::IpListenEndpoint {
            addr: Some(embassy_net::IpAddress::v4(192, 168, 178, 30)),
            port: 3005,
        })
        .unwrap();

    loop {
        let (n, ep) = socket.recv_from(&mut buf).await.unwrap();
        //if Some(embassy_net::IpAddress::v4(192, 168, 178, 30)) == ep.local_address
        //{
        if let Ok(s) = core::str::from_utf8(&buf[..n]) {
            info!("rxd from {}: {}", ep, s);
        }
        //}
    }
}

struct AppProps;

impl AppBuilder for AppProps {
    type PathRouter = impl picoserve::routing::PathRouter;

    fn build_app(self) -> picoserve::Router<Self::PathRouter> {
        picoserve::Router::new().route("/", get(|| async move { "Hello World" }))
    }
}

const WEB_TASK_POOL_SIZE: usize = 4;

#[embassy_executor::task(pool_size = WEB_TASK_POOL_SIZE)]
async fn web_task(
    id: usize,
    stack: embassy_net::Stack<'static>,
    app: &'static AppRouter<AppProps>,
    config: &'static picoserve::Config<Duration>,
) -> ! {
    let port = 80;
    let mut tcp_rx_buffer = [0; 1024];
    let mut tcp_tx_buffer = [0; 1024];
    let mut http_buffer = [0; 2048];

    picoserve::listen_and_serve(
        id,
        app,
        config,
        stack,
        port,
        &mut tcp_rx_buffer,
        &mut tcp_tx_buffer,
        &mut http_buffer,
    )
    .await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_stm32::Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hsi = Some(HSIPrescaler::DIV1);
        config.rcc.csi = true;
        config.rcc.hsi48 = Some(Default::default()); // needed for RNG
        config.rcc.pll1 = Some(Pll {
            source: PllSource::HSI,
            prediv: PllPreDiv::DIV4,
            mul: PllMul::MUL50,
            divp: Some(PllDiv::DIV2),
            divq: Some(PllDiv::DIV8), // 100mhz
            divr: None,
        });
        config.rcc.sys = Sysclk::PLL1_P; // 400 Mhz
        config.rcc.ahb_pre = AHBPrescaler::DIV2; // 200 Mhz
        config.rcc.apb1_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb2_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb3_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.apb4_pre = APBPrescaler::DIV2; // 100 Mhz
        config.rcc.voltage_scale = VoltageScale::Scale1;
        config.rcc.supply_config = SupplyConfig::DirectSMPS;
    }
    let p = embassy_stm32::init_primary(config, &SHARED_DATA);
    info!("Hello World!");

    // Generate random seed.
    let mut rng = Rng::new(p.RNG, Irqs);
    let mut seed = [0; 8];
    rng.fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    let mac_addr = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

    static PACKETS: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
    // warning: Not all STM32H7 devices have the exact same pins here
    // for STM32H747XIH, replace p.PB13 for PG12
    let device = Ethernet::new(
        PACKETS.init(PacketQueue::<4, 4>::new()),
        p.ETH,
        Irqs,
        p.PA1,  // ref_clk
        p.PA2,  // mdio
        p.PC1,  // eth_mdc
        p.PA7,  // CRS_DV: Carrier Sense
        p.PC4,  // RX_D0: Received Bit 0
        p.PC5,  // RX_D1: Received Bit 1
        p.PG13, // TX_D0: Transmit Bit 0
        p.PB13, // TX_D1: Transmit Bit 1
        p.PG11, // TX_EN: Transmit Enable
        GenericSMI::new(0),
        mac_addr,
    );

    ETH_pac.ethernet_mac().macpfr().modify(|w| w.set_pr(true));

    //let config = embassy_net::Config::dhcpv4(Default::default());
    let config = embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 178, 61), 24),
        dns_servers: Vec::new(),
        gateway: Some(Ipv4Address::new(192, 168, 178, 1)),
    });

    // Init network stack
    static RESOURCES: StaticCell<StackResources<8>> = StaticCell::new();
    let (mut stack, runner) =
        embassy_net::new(device, config, RESOURCES.init(StackResources::new()), seed);

    // Launch network task
    unwrap!(spawner.spawn(net_task(runner)));

    // Ensure DHCP configuration is up before trying connect
    //stack.wait_config_up().await;
    stack.update_ip_addrs_listen(|storage| {
        let _ = storage.push(embassy_net::IpCidr::Ipv4(Ipv4Cidr::new(
            Ipv4Address::new(192, 168, 178, 30),
            24,
        )));
    });

    info!("Network task initialized");

    let led = Output::new(p.PB14, Level::High, Speed::Low);
    unwrap!(spawner.spawn(blink(led, 1000)));

    unwrap!(spawner.spawn(udp_handler(stack)));

    let app = make_static!(AppRouter<AppProps>, AppProps.build_app());

    let config = make_static!(
        picoserve::Config<Duration>,
        picoserve::Config::new(picoserve::Timeouts {
            start_read_request: Some(Duration::from_secs(5)),
            persistent_start_read_request: Some(Duration::from_secs(1)),
            read_request: Some(Duration::from_secs(1)),
            write: Some(Duration::from_secs(1)),
        })
        .keep_connection_alive()
    );

    for id in 0..WEB_TASK_POOL_SIZE {
        spawner.must_spawn(web_task(id, stack, app, config));
    }

    let mut rx_buffer = [0; 1024];
    let mut tx_buffer = [0; 1024];
    let mut buf = [0; 1024];

    loop {
        let mut tcp_cmd_socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

        tcp_cmd_socket.set_timeout(Some(Duration::from_secs(10)));

        info!("Listening on TCP:80...");
        if let Err(e) = tcp_cmd_socket.accept(13181).await {
            warn!("accept error: {:?}", e);
            continue;
        }
        info!(
            "Received connection from {:?}",
            tcp_cmd_socket.remote_endpoint()
        );

        loop {
            let n = match tcp_cmd_socket.read(&mut buf).await {
                Ok(0) => {
                    warn!("read EOF");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    warn!("{:?}", e);
                    break;
                }
            };
            let request_str = core::str::from_utf8(&buf[..n]).unwrap();
            info!("rxd {}", request_str);

            let mut answer = "<SimDone result=\"error\" detail=\"syntax\"/>";

            if let Ok(request) = roxmltree::Document::parse(request_str) {
                if let Some(node) = request.descendants().find(|n| n.has_tag_name("SimCmd")) {
                    if node.attribute("cmd") == Some("set") {
                        if let Some(pin) = node.attribute("pin") {
                            if let Some(value) = node.attribute("value") {
                                info!("SimCmd set pin {} value {}", pin, value);
                                answer = "<SimDone result=\"ok\" detail=\"\"/>";
                            }
                        }
                    }
                }
            }

            if let Err(e) = tcp_cmd_socket.write_all(&answer.as_bytes()).await {
                warn!("write error: {:?}", e);
                break;
            }
        }
    }
}

/*
<link rel=\"icon\" href=\"data:,\">\n
└─ smoltcp::socket::tcp::{impl#9}::process @ smoltcp-0.12.0/src/macros.rs:17
170.487426 INFO  rxd GET / HTTP/1.1
Host: 192.168.178.61
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8
Accept-Language: de,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
*/

/*
loop {
    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx_buffer, &mut tx_meta, &mut tx_buffer);
    socket.bind(3005).unwrap();

    loop {
        let (n, ep) = socket.recv_from(&mut buf).await.unwrap();
        if Some(embassy_net::IpAddress::v4(192, 168, 178, 30)) == ep.local_address
        {
        if let Ok(s) = core::str::from_utf8(&buf[..n]) {
            info!("rxd from {}: {}", ep, s);
        }
    }
        //socket.send_to(&buf[..n], ep).await.unwrap();
    }
}
*/
