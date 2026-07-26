#![forbid(unsafe_code)]

pub mod aws_s3;
pub mod aws_iam;
pub mod aws_ec2;
pub mod gcp;
pub mod azure;
pub mod k8s;
pub mod docker;
pub mod kube_bench;
pub mod metadata;
pub mod error;

pub use aws_s3::S3Enumerator;
pub use aws_iam::IamAuditor;
pub use aws_ec2::Ec2Auditor;
pub use gcp::GcpEnumerator;
pub use azure::AzureEnumerator;
pub use k8s::K8sAuditor;
pub use docker::DockerAuditor;
pub use kube_bench::KubeBenchRunner;
pub use metadata::CloudMetadataApi;
pub use error::CloudSecError;
